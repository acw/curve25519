import Control.Monad(replicateM)
import Crypto.Random(CryptoRandomGen, genSeedLength, newGen)
import Crypto.Random.DRBG(HashDRBG)
import Crypto.Types(ByteLength)
import qualified Data.ByteString as BS
import Data.Tagged(Tagged, unTagged)
import Test.Framework
import Test.Framework.Providers.HUnit(testCase)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.Framework.Runners.Console(defaultMain)
import Test.HUnit(assertEqual)
import Test.QuickCheck(Arbitrary, arbitrary)

import Crypto.Curve25519.Pure

data KeyPair = KP PrivateKey PublicKey
  deriving (Show)

instance Arbitrary KeyPair where
  arbitrary =
    do let taggedSeedLen = genSeedLength :: Tagged HashDRBG ByteLength
           seedLen       = unTagged taggedSeedLen
       seedBS <- BS.pack `fmap` replicateM seedLen arbitrary
       case newGen seedBS of
         Left _ -> arbitrary
         Right g ->
           case generateKeyPair (g :: HashDRBG) of
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
