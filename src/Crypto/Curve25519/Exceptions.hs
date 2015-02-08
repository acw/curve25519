-- |An implementation of the core methods of the elliptic curve Curve25519
-- suite. These functions are largely wrappers over the curve25519-donna
-- library from Google. Note that those functions that utilize a CryptoRandomGen
-- instance may throw a GenError exception if the generator fails for any
-- reason.
module Crypto.Curve25519.Exceptions(
         PrivateKey
       , PublicKey
       , importPublic, exportPublic
       , generatePrivate
       , generatePublic
       , generateKeyPair
       , makeShared
       )
 where

import Data.ByteString(ByteString)
import Crypto.Curve25519.Pure(PublicKey, PrivateKey)
import qualified Crypto.Curve25519.Pure as Pure
import Crypto.Random

-- |Randomly generate a Curve25519 private key.
generatePrivate :: CryptoRandomGen g => g -> (PrivateKey, g)
generatePrivate g = throwLeft (Pure.generatePrivate g)

-- |Randomly generate a Curve25519 public key.
generatePublic :: PrivateKey -> PublicKey
generatePublic = Pure.generatePublic

-- |Import a public key from a ByteString. The ByteString must be exactly
-- 32 bytes long for this to work.
importPublic :: ByteString -> Maybe PublicKey
importPublic = Pure.importPublic

-- |Export a public key to a ByteString.
exportPublic :: PublicKey -> ByteString
exportPublic = Pure.exportPublic

-- |Randomly generate a key pair.
generateKeyPair :: CryptoRandomGen g => g -> (PrivateKey, PublicKey, g)
generateKeyPair g = throwLeft (Pure.generateKeyPair g)

-- |Generate a shared secret from a private key and a public key.
makeShared :: PrivateKey -> PublicKey -> ByteString
makeShared = Pure.makeShared

