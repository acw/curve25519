-- |An implementation of the core methods of the elliptic curve Curve25519
-- suite. These functions are largely wrappers over the curve25519-donna
-- library from Google. While this version is theoretically pure, in that
-- it doesn't generate any exceptions, you should be warned that it uses
-- unsafePerformIO under the hood.
module Crypto.Curve25519.Pure(
         PrivateKey
       , PublicKey
       , importPublic, exportPublic
       , importPrivate, exportPrivate
       , generatePrivate
       , generatePublic
       , generateKeyPair
       , makeShared
       )
 where

import Crypto.Random
import Data.Bits
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Alloc
import Foreign.Ptr
import System.IO.Unsafe
import Data.Maybe (fromJust)
import Data.List (foldl')

-- |The type of a Curve25519 private key.
newtype PrivateKey = Priv ByteString

-- |The type of a Curve25519 public key.
newtype PublicKey  = Pub  ByteString

instance Show PrivateKey where
  show (Priv x) = show (buildNumber x)

instance Show PublicKey where
  show (Pub x) = show (buildNumber x)

-- |Randomly generate a Curve25519 private key.
generatePrivate :: CryptoRandomGen g => g -> Either GenError (PrivateKey, g)
generatePrivate g =
  case genBytes 32 g of
    Left e              -> Left e
    Right (bytesbs, g') -> Right (fromJust (importPrivate bytesbs), g')

-- | Imports a 'ByteString' to use as private key.
-- The 'ByteString' must be exactly 32 bytes long for this to work.
--
-- Though minor changes may be made to create a valid key this property is guaranteed:
-- prop> (\x -> importPrivate x >>= (importPrivate . exportPrivate)) = importPrivate
importPrivate :: ByteString -> Maybe PrivateKey
importPrivate bstr
  | BS.length bstr /= 32 = Nothing
  | otherwise  = 
    let Just (b0, b1_31)  = BS.uncons bstr
        Just (b1_30, b31) = BS.unsnoc b1_31
        b0'               = b0   .&. 248
        b31'              = b31  .&. 127
        b31''             = b31' .|. 64
        bytes             = (b0' `BS.cons` b1_30) `BS.snoc` b31''
    in Just $ Priv bytes

-- | Export a private key to a 'ByteString'
exportPrivate :: PrivateKey -> ByteString
exportPrivate (Priv bstr) = bstr


-- |Randomly generate a Curve25519 public key.
generatePublic :: PrivateKey -> PublicKey
generatePublic (Priv priv) = Pub (curve25519 priv basePoint)

-- |Import a public key from a 'ByteString'.
-- The 'ByteString' must be exactly 32 bytes long for this to work.
importPublic :: ByteString -> Maybe PublicKey
importPublic bstr | BS.length bstr == 32 = Just (Pub bstr)
                  | otherwise            = Nothing

-- |Export a public key to a 'ByteString'.
exportPublic :: PublicKey -> ByteString
exportPublic (Pub bstr) = bstr

-- |Randomly generate a key pair.
generateKeyPair :: CryptoRandomGen g =>
                   g ->
                   Either GenError (PrivateKey, PublicKey, g)
generateKeyPair g =
  case generatePrivate g of
   Left e           -> Left e
   Right (priv, g') -> Right (priv, generatePublic priv, g')

-- |Generate a shared secret from a private key and a public key.
makeShared :: PrivateKey -> PublicKey -> ByteString
makeShared (Priv a) (Pub b) = curve25519 a b

-- Internal. A moderately evil wrapper over the core C routine.
curve25519 :: ByteString -> ByteString -> ByteString
curve25519 a b =
  unsafePerformIO $
    unsafeUseAsCString a $ \ ptra ->
      unsafeUseAsCString b $ \ ptrb ->
        do ptrc <- mallocBytes 32
           curve25519_donna ptrc ptra ptrb
           unsafePackCStringFinalizer ptrc 32 (free ptrc)

basePoint :: ByteString
basePoint = BS.cons 9 (BS.replicate 31 0)

buildNumber :: ByteString -> Integer
buildNumber bstr = foldl' run 0 (BS.unpack bstr)
 where
  run acc x = (acc `shiftL` 8) + fromIntegral x

foreign import ccall unsafe
  curve25519_donna :: Ptr Word8 -> Ptr CChar -> Ptr CChar -> IO ()
