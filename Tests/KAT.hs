{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
import Data.Char
import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import Data.Foldable (foldl')
import Data.Monoid (mconcat)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Crypto.Hash.SHA1 as SHA1

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit

v0,v1,v2 :: ByteString
v0 = ""
v1 = "The quick brown fox jumps over the lazy dog"
v2 = "The quick brown fox jumps over the lazy cog"
vectors = [ v0, v1, v2 ]

instance Arbitrary ByteString where
    arbitrary = B.pack `fmap` arbitrary

data HashFct = HashFct
    { fctHash   :: (B.ByteString -> B.ByteString)
    , fctInc    :: ([B.ByteString] -> B.ByteString) }

hashinc i u f = f . foldl u i

sha1Hash = HashFct { fctHash = SHA1.hash, fctInc = hashinc SHA1.init SHA1.update SHA1.finalize }


results :: [ (String, HashFct, [String]) ]
results = [
    ("SHA1", sha1Hash, [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" ])
    ]

hexalise s = concatMap (\c -> [ hex $ c `div` 16, hex $ c `mod` 16 ]) s
        where hex i
                | i >= 0 && i <= 9   = fromIntegral (ord '0') + i
                | i >= 10 && i <= 15 = fromIntegral (ord 'a') + i - 10
                | otherwise          = 0

hexaliseB :: B.ByteString -> B.ByteString
hexaliseB = B.pack . hexalise . B.unpack

splitB :: Int -> ByteString -> [ByteString]
splitB l b =
    if B.length b > l
        then
            let (b1, b2) = B.splitAt l b in
            b1 : splitB l b2
        else
            [ b ]

showHash :: B.ByteString -> String
showHash = map (toEnum.fromEnum) . hexalise . B.unpack

runhash hash v = showHash $ (fctHash hash) $ v
runhashinc hash v = showHash $ (fctInc hash) $ v

makeTestAlg (name, hash, results) = testGroup name $ concatMap maketest (zip3 [0..] vectors results)
    where
        runtest :: ByteString -> String
        runtest v = runhash hash v

        runtestinc :: Int -> ByteString -> String
        runtestinc i v = runhashinc hash $ splitB i v

        maketest (i, v, r) =
            [ testCase (show i ++ " one-pass") (r @=? runtest v)
            , testCase (show i ++ " inc 1") (r @=? runtestinc 1 v)
            , testCase (show i ++ " inc 2") (r @=? runtestinc 2 v)
            , testCase (show i ++ " inc 3") (r @=? runtestinc 3 v)
            , testCase (show i ++ " inc 4") (r @=? runtestinc 4 v)
            , testCase (show i ++ " inc 5") (r @=? runtestinc 5 v)
            , testCase (show i ++ " inc 9") (r @=? runtestinc 9 v)
            , testCase (show i ++ " inc 16") (r @=? runtestinc 16 v)
            ]

katTests :: [TestTree]
katTests = map makeTestAlg results


main = defaultMain $ testGroup "cryptohash"
    [ testGroup "KATs" katTests
    ]
