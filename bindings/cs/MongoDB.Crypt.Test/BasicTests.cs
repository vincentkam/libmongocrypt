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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
            return new CryptOptions(
                new AwsKmsCredentials
                {
                    AwsSecretAccessKey = "us-east-1",
                    AwsAccessKeyId = "us-east-1",
                }
            );
        }

        AwsKeyId CreateKey()
        {
            return new AwsKeyId() { CustomerMasterKey = "cmk", Region = "us-east-1" };
        }

        [Fact]
        public void EncryptQuery()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context =
                foo.StartEncryptionContext("test.test", command: BsonUtil.ToBytes(ReadJsonTestFile("cmd.json"))))
            {
                var (_, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal((ReadJsonTestFile("encrypted-command.json")));
            }
        }

        [Fact]
        public void EncryptQueryStepwise()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartEncryptionContext("test.test", command: BsonUtil.ToBytes(ReadJsonTestFile("cmd.json"))))
            {
                var (_, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal((ReadJsonTestFile("encrypted-command.json")));
            }

            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartEncryptionContext("test.test", command: BsonUtil.ToBytes(ReadJsonTestFile("cmd.json"))))
            {
                var (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
                operationSent.Should().Equal((ReadJsonTestFile("list-collections-filter.json")));

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
                operationSent.Should().Equal(ReadJsonTestFile("mongocryptd-command.json"));

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationSent.Should().Equal(ReadJsonTestFile("key-filter.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                operationSent.Should().Equal((ReadJsonTestFile("encrypted-command.json")));
            }
        }


        [Fact]
        public void DecryptQuery()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context =
                foo.StartDecryptionContext(BsonUtil.ToBytes(ReadJsonTestFile("encrypted-command-reply.json"))))
            {
                var (_, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal(ReadJsonTestFile("command-reply.json"));
            }
        }

        [Fact]
        public void DecryptQueryStepwise()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartDecryptionContext(BsonUtil.ToBytes(ReadJsonTestFile("encrypted-command-reply.json"))))
            {
                var (state, _, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationProduced.Should().Equal(ReadJsonTestFile("key-filter.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                operationProduced.Should().Equal(ReadJsonTestFile("command-reply.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_DONE);
            }
        }

        [Fact]
        public void EncryptBadBson()
        {
            using (var foo = CryptClientFactory.Create(CreateOptions()))
            using (var context = foo.StartEncryptionContext("test.test",  command: new byte[] {0x2, 0x3}))
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
            var keyDoc = ReadJsonTestFile("key-document.json");
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
                    var reply = ReadJsonTestFile("collection-info.json");
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
                    var reply = ReadJsonTestFile("mongocryptd-reply.json");
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
                    var reply = ReadJsonTestFile("key-document.json");
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

                case CryptContext.StateCode.MONGOCRYPT_CTX_ERROR:
                {
                    // We expect exceptions are thrown before we get to this state
                    throw new NotImplementedException();
                }
            }

            throw new NotImplementedException();
        }

        static IEnumerable<string> FindTestDirectories()
        {
            // Assume we are child directory of the repo
            string searchPath = Path.Combine("..", "test", "example");
            string cwd = Directory.GetCurrentDirectory();
            var testDirs = new List<string>();
            for(int i = 0; i < 10; i++)
            {
                string testPath = Path.Combine(cwd, searchPath);
                if (Directory.Exists(testPath))
                {
                    testDirs.Add(testPath);
                }

                searchPath = Path.Combine("..", searchPath);
            }

            if (testDirs.Count == 0)
            {
                throw new DirectoryNotFoundException("test/example");
            }

            return testDirs;
        }


        static string ReadHttpTestFile(string file)
        {
            // The HTTP tests assume \r\n
            // And git strips \r on Unix machines by default so fix up the files

            var text = ReadTestFile(file);

            StringBuilder builder = new StringBuilder(text.Length);
            for(int i = 0; i < text.Length; i++) {
                if(text[i] == '\n' && text[i - 1] != '\r' )
                    builder.Append('\r');
                builder.Append(text[i]);
            }
            return builder.ToString();
        }

        static BsonDocument ReadJsonTestFile(string file)
        {
            var text = ReadTestFile(file);

            // Work around C# drivers and C driver have different extended json support
            text = text.Replace("\"$numberLong\"", "$numberLong");

            return BsonUtil.FromJSON(text);
        }

        static string ReadTestFile(string fileName)
        {
            return FindTestDirectories()
                .Select(directory => Path.Combine(directory, fileName))
                .Select(path => File.Exists(path) ? File.ReadAllText(path) : null)
                .FirstOrDefault(httpText => httpText != null);
        }
    }
}
