/*
 * Copyright 2019–present MongoDB, Inc.
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

using System.Collections.Generic;
using System.Linq;

namespace MongoDB.Crypt
{
    /// <summary>
    /// Options to configure mongocrypt with.
    /// </summary>
    public class CryptOptions
    {
        public readonly Dictionary<KmsType, IKmsCredentials> KmsCredentialsOptions = new Dictionary<KmsType, IKmsCredentials>();
        public byte[] Schema { get; }

        public CryptOptions(IKmsCredentials kmsCredentials) : this(kmsCredentials, null)
        {
        }

        public CryptOptions(IKmsCredentials kmsCredential, byte[] schema) : this(new[] { kmsCredential }, schema)
        {
        }

        public CryptOptions(IEnumerable<IKmsCredentials> kmsCredentials) : this(kmsCredentials, null)
        {
        }

        public CryptOptions(IEnumerable<IKmsCredentials> kmsCredentials, byte[] schema)
        {
            InitializeKmsCredentials(kmsCredentials.ToList());
            Schema = schema;
        }

        private void InitializeKmsCredentials(List<IKmsCredentials> kmsCredentials)
        {
            if (kmsCredentials != null && kmsCredentials.Count != 0)
            {
                foreach (var kmsCredential in kmsCredentials)
                {
                    if (KmsCredentialsOptions.ContainsKey(kmsCredential.KmsType))
                    {
                        KmsCredentialsOptions[kmsCredential.KmsType] = kmsCredential;
                    }
                    else
                    {
                        KmsCredentialsOptions.Add(kmsCredential.KmsType, kmsCredential);
                    }
                }
            }
        }

        // TODO: - add configurable logging support
    }
}
