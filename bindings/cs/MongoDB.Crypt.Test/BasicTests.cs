﻿/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using MongoDB.Bson;
using System;
using System.Diagnostics;
using System.IO;
using Xunit;
using System.Text;
using FluentAssertions;
using Xunit.Abstractions;

namespace MongoDB.Crypt.Test
{
    public class BasicTests
    {
        private readonly ITestOutputHelper _output;

        public BasicTests(ITestOutputHelper output)
        {
            _output = output;
        }
        
        CryptOptions CreateOptions()
        {
            return new CryptOptions
            {
                KmsCredentials = new AwsKmsCredentials
                {
                    AwsSecretAccessKey = "us-east-1",
                    AwsAccessKeyId = "us-east-1",
                }
            };
        }

        AwsKeyId CreateKey()
        {
            return new AwsKeyId() { CustomerMasterKey = "cmk", Region = "us-east-1" };
        }

        [Fact]
        public void EncryptQuery()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartEncryptionContext("test.test", null))
            {
                var (bsonCommand, binaryCommand) = ProcessContextToCompletion(context);

                bsonCommand.Should().Equal(ReadJSONTestFile("encrypted-command.json"));
            }
        }

        [Fact]
        public void DecryptQuery()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartDecryptionContext(BsonUtil.ToBytes(ReadJSONTestFile("encrypted-document.json"))))
            {
                var (bsonCommand, binaryCommand) = ProcessContextToCompletion(context);
            }
        }

        [Fact]
        public void EncryptBadBSON()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartEncryptionContext("test.test", null))
            {
                var binary = context.GetOperation();
                var doc = BsonUtil.ToDocument(binary);
                _output.WriteLine("ListCollections: " + doc);

                // Ensure if we encrypt non-sense, it throws an exception demonstrating our exception code is good
                Action act = () => context.Feed(new byte[] {0x1, 0x2, 0x3});
                var exception = Record.Exception(act);

                exception.Should().BeOfType<CryptException>();
            }
        }

        [Fact]
        public void EncryptExplicit()
        {
            var keyDoc = ReadJSONTestFile("key-document.json");
            Guid key = keyDoc["_id"].AsGuid;


            BsonDocument doc = new BsonDocument()
            {
                {  "v" , "hello" },
            };

            var testData = BsonUtil.ToBytes(doc);

            byte[] encryptedResult;
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartExplicitEncryptionContext(key, Alogrithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, testData, null))
            {
                (_, encryptedResult) = ProcessContextToCompletion(context);
            }

            byte[] decryptedResult;

            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartExplicitDecryptionContext(encryptedResult))
            {
                (_, decryptedResult) = ProcessContextToCompletion(context);
            }

            decryptedResult.Should().Equal(testData);
        }

        private (BsonDocument document, byte[] buffer) ProcessContextToCompletion(CryptContext context)
        {
            CryptContext.StateCode state;
            BsonDocument document = null;
            byte[] buffer = null;

            while (!context.IsDone)
            {
                (_, document, buffer) = ProcessState(context);
            }

            return (document, buffer);
        }

        private (CryptContext.StateCode state, BsonDocument document, byte[] buffer) ProcessState(CryptContext context)
        {
            _output.WriteLine("\n----------------------------------\nState:" + context.State);
            switch (context.State)
            {
                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
                {
                    var binary = context.GetOperation();
                    var doc = BsonUtil.ToDocument(binary);
                    _output.WriteLine("ListCollections: " + doc);
                    var reply = ReadJSONTestFile("collection-info.json");
                    _output.WriteLine("Reply:" + reply);
                    context.Feed(BsonUtil.ToBytes(reply));
                    context.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
                {
                    var binary = context.GetOperation();
                    var doc = BsonUtil.ToDocument(binary);
                    _output.WriteLine("Markings: " + doc);
                    var reply = ReadJSONTestFile("mongocryptd-reply.json");
                    _output.WriteLine("Reply:" + reply);
                    context.Feed(BsonUtil.ToBytes(reply));
                    context.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS:
                {
                    var binary = context.GetOperation();
                    var doc = BsonUtil.ToDocument(binary);
                    _output.WriteLine("Key Document: " + doc);
                    var reply = ReadJSONTestFile("key-document.json");
                    _output.WriteLine("Reply:" + reply);
                    context.Feed(BsonUtil.ToBytes(reply));
                    context.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS:
                {
                    var requests = context.GetKmsMessageRequests();
                    foreach (var req in requests)
                    {
                        var binary = req.Message;
                        _output.WriteLine("Key Document: " + binary);
                        var reply = ReadHttpTestFile("kms-decrypt-reply.txt");
                        _output.WriteLine("Reply:" + reply);
                        req.Feed(Encoding.UTF8.GetBytes(reply));
                        req.BytesNeeded.Should().Be(0);
                    }

                    requests.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_READY:
                {
                    Binary b = context.FinalizeForEncryption();
                    _output.WriteLine("Buffer:" + b.ToArray());
                    var document = BsonUtil.ToDocument(b);
                    var buffer = b.ToArray();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_READY, document, buffer);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_DONE:
                {
                    _output.WriteLine("DONE!!");
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_DONE, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NOTHING_TO_DO:
                {
                    _output.WriteLine("NOTHING TO DO");
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_DONE, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_ERROR:
                {
                    // We expect exceptions are thrown before we get to this state
                    throw new NotImplementedException();
                }
            }

            throw new NotImplementedException();
        }

        static string FindTestDirectory()
        {
            // Assume we are child directory of the repo
            string searchPath = Path.Combine("..", "test", "example");
            string cwd = Directory.GetCurrentDirectory();
            for(int i = 0; i < 10; i++)
            {
                string testPath = Path.Combine(cwd, searchPath);
                if (Directory.Exists(testPath))
                {
                    return testPath;
                }

                searchPath = Path.Combine("..", searchPath);
            }

            throw new DirectoryNotFoundException("test/example");
        }


        static string ReadHttpTestFile(string file)
        {
            // The HTTP tests assume \r\n
            // And git strips \r on Unix machines by default so fix up the files
            string root = FindTestDirectory();
            string full = Path.Combine(root, file);
            string text = File.ReadAllText(full);

            StringBuilder builder = new StringBuilder(text.Length);
            for(int i = 0; i < text.Length; i++) {
                if(text[i] == '\n' && text[i - 1] != '\r' )
                    builder.Append('\r');
            builder.Append(text[i]);
            }
            return builder.ToString();
        }

        static BsonDocument ReadJSONTestFile(string file)
        {
            string root = FindTestDirectory();
            string full = Path.Combine(root, file);
            string text = File.ReadAllText(full);

            // Work around C# drivers and C driver have different extended json support
            text = text.Replace("\"$numberLong\"", "$numberLong");

            return BsonUtil.FromJSON(text);
        }
    }
}
