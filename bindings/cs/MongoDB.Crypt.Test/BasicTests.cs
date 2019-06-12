/*
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
                var (binaryCommand, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal((ReadJSONTestFile("encrypted-command.json")));
            }

            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartEncryptionContext("test.test", null))
            {
                var (state, binarySent, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
                operationSent.Should().Equal((ReadJSONTestFile("list-collections-filter.json")));

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
                operationSent.Should().Equal(ReadJSONTestFile("json-schema.json"));

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationSent.Should().Equal(ReadJSONTestFile("key-filter.json"));

                (state, binarySent, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                operationSent.Should().Equal((ReadJSONTestFile("encrypted-command.json")));
            }
        }

        [Fact]
        public void DecryptQuery()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartDecryptionContext(BsonUtil.ToBytes(ReadJSONTestFile("encrypted-document.json"))))
            {
                var (binaryCommand, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal(new BsonDocument("ssn", "457-55-5462"));
            }

            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartDecryptionContext(BsonUtil.ToBytes(ReadJSONTestFile("encrypted-document.json"))))
            {
                var (state, binaryProduced, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationProduced.Should().Equal(ReadJSONTestFile("key-filter.json"));

                (state, binaryProduced, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                var decryptedDocument = operationProduced; // todo: fix naming problem
                operationProduced.Should().Equal(new BsonDocument("ssn", "457-55-5462"));

                (state, _, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_DONE);
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

            Binary encryptedResult;
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartExplicitEncryptionContext(key, Alogrithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, testData, null))
            {
                (encryptedResult, _) = ProcessContextToCompletion(context);
            }


            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartExplicitDecryptionContext(encryptedResult.ToArray()))
            {
                var (decryptedResult, _) = ProcessContextToCompletion(context);

                decryptedResult.ToArray().Should().Equal(testData);
            }


        }

        private (Binary binarySent, BsonDocument document) ProcessContextToCompletion(CryptContext context)
        {
            CryptContext.StateCode state;
            BsonDocument document = null;
            Binary binary = null;

            while (!context.IsDone)
            {
                (_, binary, document) = ProcessState(context);
            }

            return (binary, document);
        }

        /// <summary>
        /// Processes the current state, simulating the execution the operation/post requests needed to reach the next state
        /// Returns (stateProcessed, binaryOperationProduced, bsonOperationProduced)
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private (CryptContext.StateCode stateProcessed, Binary binaryProduced, BsonDocument bsonOperationProduced) ProcessState(CryptContext context)
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
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO, binary, doc);
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
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS, binary, doc);
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
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS, binary, doc);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS:
                {
                    var requests = context.GetKmsMessageRequests();
                    foreach (var req in requests)
                    {
                        var binary = req.Message;
                        _output.WriteLine("Key Document: " + binary);
                        var postRequest = binary.ToString();
                        postRequest.Should().Contain("Host:kms.us-east-1.amazonaws.com");

                        var reply = ReadHttpTestFile("kms-decrypt-reply.txt");
                        _output.WriteLine("Reply: " + reply);
                        req.Feed(Encoding.UTF8.GetBytes(reply));
                        req.BytesNeeded.Should().Be(0);
                    }

                    requests.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_READY:
                {
                    Binary binary = context.FinalizeForEncryption();
                    _output.WriteLine("Buffer:" + binary.ToArray());
                    var document = BsonUtil.ToDocument(binary);
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_READY, binary, document);
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
