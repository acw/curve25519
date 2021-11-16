import Control.Monad(replicateM)
import Crypto.Random(CryptoRandomGen(..), GenError(..), ReseedInfo(..), genSeedLength, newGen)
import Crypto.Types(ByteLength)
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.Tagged(Tagged(..), unTagged)
import Data.Word(Word64)
import Test.Framework
import Test.Framework.Providers.HUnit(testCase)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.Framework.Runners.Console(defaultMain)
import Test.HUnit(assertEqual)
import Test.QuickCheck(Arbitrary, arbitrary)

import Crypto.Curve25519.Pure

data KeyPair = KP PrivateKey PublicKey
  deriving (Show)

data FakeRandom = FakeRandom ByteString

randomBufferSize :: Word64
randomBufferSize = 512

instance CryptoRandomGen FakeRandom where
  newGen = Right . FakeRandom
  genSeedLength = Tagged (fromIntegral randomBufferSize)
  genBytes len (FakeRandom bs)
    | BS.length bs < len = Left RequestedTooManyBytes
    | (retval, rest) <- BS.splitAt len bs = Right (retval, FakeRandom rest)
  reseedInfo (FakeRandom bs) = InXBytes (fromIntegral (BS.length bs))
  reseedPeriod _ = InXBytes randomBufferSize
  genBytesWithEntropy len rest (FakeRandom bs) =  genBytes len (FakeRandom (BS.append bs rest))
  reseed new (FakeRandom old) = Right (FakeRandom (old `BS.append` new))

instance Arbitrary KeyPair where
  arbitrary =
    do let taggedSeedLen = genSeedLength :: Tagged FakeRandom ByteLength
           seedLen       = unTagged taggedSeedLen
       seedBS <- BS.pack `fmap` replicateM seedLen arbitrary
       case newGen seedBS of
         Left _ -> arbitrary
         Right g ->
           case generateKeyPair (g :: FakeRandom) of
             Left _ -> arbitrary
             Right (priv, pub, _) -> return (KP priv pub)

prop_agreementWorks :: KeyPair -> KeyPair -> Bool
prop_agreementWorks (KP privx pubX) (KP privy pubY) = a == b
 where
  a = makeShared privx pubY
  b = makeShared privy pubX

main :: IO ()
main = defaultMain [ctest, qtest]
 where
  ctest = testCase "Internal C Tests" (assertEqual "" (ctest_main 1) 0)
  qtest = testProperty "Haskell Agreement Tests" prop_agreementWorks

foreign import ccall ctest_main :: Int -> Int
