package com.Concordia;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class Main {

    public int generateRandomPrimeNumber() {
        int maxRange = (int) Math.pow(2.0, 16.0);
        int randomPrimeNumber = 0;
        for (int i = 0; i < maxRange; i++) {
            //Generating random number between 32768 and 65536 as numbers below this range are not 16-bit.
            randomPrimeNumber = ThreadLocalRandom.current().nextInt(32768, maxRange);
            if (isPrime(randomPrimeNumber)) break;
        }
        return randomPrimeNumber;
    }

    public boolean isPrime(int number) {
        BigInteger bigInteger = BigInteger.valueOf(number);
        return bigInteger.isProbablePrime(number);
    }

    public long selectPublicKey(long phiOfN) {
        long generatedLong = 1;
        for (int i = 2; i < phiOfN; i = i + 1) {
            long leftLimit = 1;
            // Generating a random number between 1 and phiOfN for e
            generatedLong = leftLimit + (long) ((Math.random() / 100) * (phiOfN - leftLimit));
            //checking if GCD(e,PhiOfN) equals 1
            if (checkCoPrimality(phiOfN, generatedLong)) break;
        }
        return generatedLong;
    }

    static boolean checkCoPrimality(long a, long b) {
        long phi = a, e = b;
        long rem = 10;
        while (rem != 0 && rem != 1) {
            rem = a % b;
            a = b;
            b = rem;
        }
        if (rem == 1) {
            System.out.println("Generated number e=" + e + " and PhiOfN=" + phi + " are co-primes");
        } else {
            System.out.println("Generated number e=" + e + " and PhiOfN=" + phi + " are not co-primes");
        }
        return rem == 1;
    }


    public long computeSecretKey(long e, long phiOfN) {
        for (int i = 1; i < phiOfN; i++)
            if (((e % phiOfN) * (i % phiOfN)) % phiOfN == 1)
                return i;
        return 1;
    }

    static String[] breakUpMessage(String str) {
        char[] charArray = str.toCharArray();
        int arraySize = str.length() % 3 != 0 ? (str.length() + 1) / 3 : str.length() / 3;
        String[] messageArray = new String[arraySize];

        int index = 0;
        for (int i = 0; i < messageArray.length; i++) {
            char[] subArray= new char[3];
            if (str.length() - index < 3) {
                subArray = new char[2];
            }
            for (int j = 0; j < 3 && index < str.length(); j++) {
                subArray[j] = charArray[index];
                index++;
            }
            messageArray[i] = String.valueOf(subArray);
        }
        return messageArray;
    }

    static String[] convertStringToHex(String[] str) {
        String[] hexCodes = new String[str.length];
        for (int i = 0; i < str.length; i++) {
            String s = str[i];
            StringBuilder hexCode = new StringBuilder();
            for (int j = 0; j < s.length(); j++) {
                if (s.charAt(j) == 0) {
                    continue;
                }
                int z = s.charAt(j);
                String partHexCode = Integer.toHexString(z);
                hexCode.append(partHexCode);
            }
            hexCodes[i] = hexCode.toString();
        }
        return hexCodes;
    }

    static int[] convertHexToInt(String[] str) {
        int[] intCodes = new int[str.length];
        for (int i = 0; i < str.length; i++) {
            intCodes[i] = Integer.parseInt(str[i], 16);
        }
        return intCodes;
    }


    static long encryptUsingSquareAndMultiply(long e, long m, long N) {
        char[] binaryRep = Integer.toBinaryString((int) e).toCharArray();
        long res = (m * m) % N;
        long[] squaredRes = new long[binaryRep.length];
        squaredRes[squaredRes.length - 1] = m;
        squaredRes[squaredRes.length - 2] = res;
        for (int i = squaredRes.length - 3; i >= 0; i--) {
            squaredRes[i] = (squaredRes[i + 1] * squaredRes[i + 1]) % N;
        }
        long product = 1;
        for (int i = 0; i < binaryRep.length; i++) {
            if (binaryRep[i] == '1') {
                product *= squaredRes[i];
                if (product > N) {
                    product %= N;
                }
            }
        }
        if (product > N) {
            product %= N;
        }
        return product;
    }

    static long decryptUsingSquareAndMultiply(long d, long c, long N) {
        char[] binaryRep = Integer.toBinaryString((int) d).toCharArray();
        long res = (c * c) % N;
        long[] squaredRes = new long[binaryRep.length];
        squaredRes[squaredRes.length - 1] = c;
        squaredRes[squaredRes.length - 2] = res;
        for (int i = squaredRes.length - 3; i >= 0; i--) {
            long x = squaredRes[i + 1] * squaredRes[i + 1];
            squaredRes[i] = (x) % N;
        }
        long product = 1;
        for (int i = 0; i < binaryRep.length; i++) {
            if (binaryRep[i] == '1') {
                product *= squaredRes[i];
                if (product > N) {
                    product %= N;
                }
            }
        }
        if (product > N) {
            product %= N;
        }
        return product;
    }

    static String[] convertIntToHex(long[] decryptedMessageList) {
        String[] hexList = new String[decryptedMessageList.length];
        for (int i = 0; i < decryptedMessageList.length; i++) {
            hexList[i] = Long.toHexString(decryptedMessageList[i]);
        }
        return hexList;
    }

    static String HexToString(String hexValue) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexValue.length() - 1; i += 2) {
            String str = hexValue.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    static String decryptedMessageReConstruction(String[] stringList) {
        StringBuilder str = new StringBuilder();
        for (String s : stringList) {
            str.append(s);
        }
        return str.toString();
    }

    static long[] messageSigning(String messageToBeSigned, long d, long N) {
        String[] messageToBeSignedChunks = breakUpMessage(messageToBeSigned);
        String[] messageToSignedHexChunks = convertStringToHex(messageToBeSignedChunks);
        int[] signedIntCodes = convertHexToInt(messageToSignedHexChunks);
        long[] messageSignature = new long[signedIntCodes.length];
        for (int i = 0; i < signedIntCodes.length; i++) {
            messageSignature[i] = encryptUsingSquareAndMultiply(d, signedIntCodes[i], N);
        }
        return messageSignature;
    }

    static boolean signatureVerification(String actualPartnerSignature,String partnerMessage) {
        return actualPartnerSignature.equals(partnerMessage);
    }

    static String signatureDecryption(long[] partnerSignature, long N, long d) {
        long[] decryptedSigList = new long[partnerSignature.length];
        for (int i = 0; i < partnerSignature.length; i++) {
            decryptedSigList[i] = decryptUsingSquareAndMultiply(d,partnerSignature[i], N);
        }
        String[] decryptedHexList = convertIntToHex(decryptedSigList);
        String[] decryptedMessageList = new String[decryptedHexList.length];
        for (int i = 0; i < decryptedHexList.length; i++) {
            decryptedMessageList[i] = HexToString(decryptedHexList[i]);
        }
        return decryptedMessageReConstruction(decryptedMessageList);
    }

    public static void main(String[] args) {

        //Starter Code to generate my P and Q. And Verifying correctness of e and d through encryption and decryption.

//        Main main = new Main();
//        int p=main.generateRandomPrimeNumber();
//        int q=main.generateRandomPrimeNumber();
//        long N = (long)p * (long)q;
//        long phiOfN = (long)(p - 1) * (long)(q - 1);
//        System.out.println("Generating P and Q");
//        System.out.println("P="+p);
//        System.out.println("Q=" + q);
//        System.out.println("N=" + N);
//        System.out.println("PhiOfN=" + phiOfN);
//        System.out.println("-----------Finding e and Computing d -------------------------");
//        long e = main.selectPublicKey(phiOfN);
//        long d = main.computeSecretKey(e, phiOfN);
//        if (d < 0) {
//            d += phiOfN;
//        }
//        System.out.println("d=" + d);
//        System.out.println("---------Checking encryption and decryption-----------------");
//        int m = 21;
//        System.out.println("Entered Message m: "+m);
//        long c = main.encryptMessage(e, m, N);
//        System.out.println("Encrypted Message: " + c);
//        long decodedMessage = main.decryptMessage(d, c, N);
//        System.out.println("Decrypted Message: " + decodedMessage);

        System.out.println("# IDs ");
        System.out.println("MY_ID = 40185178");
        System.out.println("PARTNER_ID = 40192678");
        System.out.println();
        long my_N = 3077914817L;
        long d = 701564699;
        //My Data
        int p = 55547, q = 55411;
        long phiOfN = (long) (p - 1) * (long) (q - 1);
        long my_e = 8970179;
        System.out.println("# my data");
        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("N = " + my_N);
        System.out.println("phi_N = " + phiOfN);
        System.out.println("e = " + my_e);
        System.out.println("d = " + d);
        //partner's N and e
        long partner_N = 2484554911L;
        long partner_e = 52424747;
        System.out.println();
        System.out.println("# my partner data");
        System.out.println("PARTNER_N = " + partner_N);
        System.out.println("PARTNER_e = " + partner_e);
        String message = "Hello. How are you? My name is Syed.";
        System.out.println();
        System.out.println("# encryption");
        System.out.println("MY_MESSAGE = " + message);
        String[] str = breakUpMessage(message);
        System.out.println("MY_MESSAGE_chunks = " + Arrays.toString(str));
        String[] hexCodes = convertStringToHex(str);
        int[] intCodes = convertHexToInt(hexCodes);
        long[] encryptedMessageList = new long[intCodes.length];
        for (int i = 0; i < intCodes.length; i++) {
            encryptedMessageList[i] = encryptUsingSquareAndMultiply(partner_e, intCodes[i], partner_N);
        }
        System.out.println("MY_CIPHERTEXT = " + Arrays.toString(encryptedMessageList));

        //Partner's encrypted text taken from the database
        long[] partnerEncryptedMessageList = {1467714802, 1291406461, 1110592414, 1110592414, 226369641, 2891109948L, 1565703138};
        long[] partnerDecryptedMessageList = new long[partnerEncryptedMessageList.length];
        for (int i = 0; i < partnerEncryptedMessageList.length; i++) {
            partnerDecryptedMessageList[i] = decryptUsingSquareAndMultiply(d, partnerEncryptedMessageList[i], my_N);
        }
        System.out.println();
        System.out.println("# decryption");
        System.out.println("PARTNER_CIPHERTEXT = " + Arrays.toString(partnerEncryptedMessageList));
        String[] decryptedHexList = convertIntToHex(partnerDecryptedMessageList);
        String[] decryptedMessageList = new String[decryptedHexList.length];
        for (int i = 0; i < decryptedHexList.length; i++) {
            decryptedMessageList[i] = HexToString(decryptedHexList[i]);
        }
        System.out.println("PARTNER_MESSAGE_chunks_AFTER_DECRYPT = " + Arrays.toString(decryptedMessageList));
        String decryptedMessage = decryptedMessageReConstruction(decryptedMessageList);
        System.out.println("PARTNER_MESSAGE_AFTER_DECRYPT = " + decryptedMessage);
        System.out.println();
        System.out.println("# sign");
        String messageSignatureString = "Syed Abdussami";
        long[] message_signature = messageSigning(messageSignatureString, d, my_N);
        System.out.println("MY_MESSAGE_TO_BE_SIGNED = " + messageSignatureString);
        System.out.println("MY_MESSAGE_TO_BE_SIGNED_chunks = " + Arrays.toString(breakUpMessage(messageSignatureString)));
        System.out.println("MY_SIGNATURE = " + Arrays.toString(message_signature));

        //Partner's Signature array as received from the database
        long[] partnerSignature = {466936983, 333568137, 218420002, 2272663950L, 1379602755, 1413952578, 1238932493};
        String decryptedPartnerSign=signatureDecryption(partnerSignature, partner_N, partner_e);

        //Partner Signature Verification
        //Taking the partner signature message from the database
        String partnerMessage="Henisha Panchhiwala";
        boolean is_signature_valid=signatureVerification(decryptedPartnerSign,partnerMessage);
        System.out.println();
        System.out.println("# verify the signature");
        System.out.println("PARTNER_SIGNED_MESSAGE = "+decryptedPartnerSign);
        System.out.println("PARTNER_SIGNATURE = "+ Arrays.toString(partnerSignature));
        System.out.println("#IS_VALID_SIGNATURE should be True or False");
        System.out.println("IS_VALID_SIGNATURE = "+is_signature_valid);

        System.out.println();
        System.out.println();
        System.out.println("COMMENTS = \"I have done my project in java and used intellij as my IDE.\"");
    }
}
