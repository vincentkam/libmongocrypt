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

namespace MongoDB.Crypt
{
    /// <summary>
    /// Interface for KMS Key Information
    /// </summary>
    public interface IKmsKeyId
    {
        /// <summary>
        /// Gets the type of the KMS key.
        /// </summary>
        /// <value>
        /// The type of the KMS key.
        /// </value>
        KmsType KeyType { get; }

        /// <summary>
        /// Gets the alternate key names as byte arrays.
        /// Each byte array describes an alternative key name via a BsonDocument in the following format:
        ///  { "keyAltName" : [BSON UTF8 value] }
        /// </summary>
        /// <value>The alternate key names.</value>
        IEnumerable<byte[]> AlternateKeyNames { get; }
    }

    /// <summary>
    /// An internal interface that all IKmsKeyId must implement
    /// because methods of an interface cannot have access modifiers.
    /// </summary>
    internal interface IInternalKmsKeyId
    {
        void SetCredentials(ContextSafeHandle handle, Status status);
        void SetAlternateKeyNames(ContextSafeHandle handle, Status status);
    }

    /// <summary>
    /// Using extension methods in lieu of default interface methods that will not be available until C#8 releases
    /// </summary>
    internal static class KmsExtensions
    {
        internal static void SetAlternateKeyNames(this IKmsKeyId kmsKeyId, ContextSafeHandle handle, Status status)
        {
            foreach (var alternateKeyName in kmsKeyId.AlternateKeyNames)
            {
                unsafe
                {
                    fixed (byte* p = alternateKeyName)
                    {
                        IntPtr ptr = (IntPtr)p;
                        using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)alternateKeyName.Length))
                        {
                            handle.Check( status, Library.mongocrypt_ctx_setopt_key_alt_name(handle, pinned.Handle));
                        }
                    }
                }
            }
        }

    }
}
