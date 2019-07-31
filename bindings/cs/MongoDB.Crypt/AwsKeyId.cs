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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

namespace MongoDB.Crypt
{
    /// <summary>Contains all the information needed to find a AWS KMS CMK.</summary>
    public class AwsKeyId : IKmsKeyId, IInternalKmsKeyId
    {
        public KmsType KeyType => KmsType.Aws;

        /// <summary>
        /// Creates an <see cref="AwsKeyId"/> class.
        /// </summary>
        /// <param name="customerMasterKey">The customerMasterKey.</param>
        /// <param name="region">The region.</param>
        public AwsKeyId(string customerMasterKey, string region)
        {
            Region = region;
            CustomerMasterKey = customerMasterKey;
            AlternateKeyNames = new List<byte[]>().AsReadOnly();
        }

        /// <summary>
        /// Creates an <see cref="AwsKeyId"/> class.
        /// </summary>
        /// <param name="customerMasterKey">The customerMasterKey.</param>
        /// <param name="region">The region.</param>
        /// <param name="alternateKeyNames">The alternate key names.</param>
        public AwsKeyId(string customerMasterKey, string region, IEnumerable<byte[]> alternateKeyNames)
        {
            Region = region;
            CustomerMasterKey = customerMasterKey;
            AlternateKeyNames = alternateKeyNames;
        }

        public IEnumerable<byte[]> AlternateKeyNames { get; }

        /// <summary>Gets the region.</summary>
        /// <value>The region.</value>
        public string Region { get; }

        /// <summary>
        /// Gets the customer master key.
        /// </summary>
        /// <value>
        /// The customer master key.
        /// </value>
        public string CustomerMasterKey { get; }

        void IInternalKmsKeyId.SetCredentials(ContextSafeHandle handle, Status status)
        {
            IntPtr regionPointer = (IntPtr)Marshal.StringToHGlobalAnsi(Region);

            try
            {
                IntPtr keyPointer = (IntPtr)Marshal.StringToHGlobalAnsi(CustomerMasterKey);
                try
                {
                    // Let mongocrypt run strlen
                    handle.Check(
                        status,
                        Library.mongocrypt_ctx_setopt_masterkey_aws(handle, regionPointer, -1, keyPointer, -1));
                    ((IInternalKmsKeyId) this).SetAlternateKeyNames(handle, status);
                }
                finally
                {
                    Marshal.FreeHGlobal(keyPointer);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(regionPointer);
            }
        }

        void IInternalKmsKeyId.SetAlternateKeyNames(ContextSafeHandle handle, Status status)
        {
            this.SetAlternateKeyNames(handle, status);
        }
    }
}
