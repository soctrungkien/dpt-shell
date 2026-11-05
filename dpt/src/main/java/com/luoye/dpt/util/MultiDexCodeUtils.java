package com.luoye.dpt.util;

import com.luoye.dpt.config.Const;
import com.luoye.dpt.model.DexCode;
import com.luoye.dpt.model.Instruction;
import com.luoye.dpt.model.MultiDexCode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author luoyesiqiu
 */
public class MultiDexCodeUtils {

    private static final int CODE_ITEM_NONCE_SIZE = 16;

    public static MultiDexCode makeMultiDexCode(Map<Integer, List<Instruction>> multiDexInsns) {
        int fileOffset = 0;
        MultiDexCode multiDexCode = new MultiDexCode();
        multiDexCode.setVersion(Const.MULTI_DEX_CODE_VERSION);
        fileOffset += 2;
        multiDexCode.setDexCount((short) multiDexInsns.size());
        fileOffset += 2;
        List<Integer> dexCodeIndex = new ArrayList<>();
        multiDexCode.setDexCodesIndex(dexCodeIndex);
        fileOffset += 4 * multiDexInsns.size();

        List<DexCode> dexCodeList = new ArrayList<>();
        List<Integer> insnsIndexList = new ArrayList<>();
        Iterator<Map.Entry<Integer, List<Instruction>>> iterator = multiDexInsns.entrySet()
                                                                                .iterator();
        while (iterator.hasNext()) {
            List<Instruction> insns = iterator.next().getValue();
            if (insns == null) {
                continue;
            }
            dexCodeIndex.add(fileOffset);
            DexCode dexCode = new DexCode();

            dexCode.setMethodCount((short) insns.size());
            fileOffset += 2;
            dexCode.setInsns(insns);

            insnsIndexList.add(fileOffset);

            dexCode.setInsnsIndex(insnsIndexList);

            for (Instruction ins : insns) {
                fileOffset += 4; //Instruction.methodIndex
                fileOffset += 4; //Instruction.instructionDataSize
                fileOffset += ins.getInstructionsData().length; //Instruction.instructionsData
            }

            dexCodeList.add(dexCode);
        }

        multiDexCode.setDexCodes(dexCodeList);

        return multiDexCode;
    }

    /**
     * Serialize MultiDexCode struct to a little-endian byte array.
     */
    public static byte[] makeMultiDexCodeBytes(MultiDexCode multiDexCode) {
        if (multiDexCode.getDexCodes() == null || multiDexCode.getDexCodes().isEmpty()) {
            return null;
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            //Write file version
            out.write(Endian.makeLittleEndian(multiDexCode.getVersion()));
            //Write dex count
            out.write(Endian.makeLittleEndian(multiDexCode.getDexCount()));

            //Write to the location of each dex in the file
            for (Integer dexCodesIndex : multiDexCode.getDexCodesIndex()) {
                out.write(Endian.makeLittleEndian(dexCodesIndex));
            }
            //Write data for each dex
            for (DexCode dexCode : multiDexCode.getDexCodes()) {
                List<Instruction> insns = dexCode.getInsns();

                //The number of functions that are written to a single dex
                out.write(Endian.makeLittleEndian(dexCode.getMethodCount()));
                for (Instruction instruction : insns) {
                    out.write(Endian.makeLittleEndian(instruction.getMethodIndex()));
                    out.write(Endian.makeLittleEndian(instruction.getInstructionDataSize()));
                    out.write(instruction.getInstructionsData());
                }
            }

            return out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Write MultiDexCode struct to file
     */
    public static void writeMultiDexCode(String out, MultiDexCode multiDexCode) {
        byte[] data = makeMultiDexCodeBytes(multiDexCode);
        if (data == null) {
            return;
        }
        IoUtils.writeFile(out, data);
    }

    /**
     * Encrypt the whole code-item file:
     *   [16-byte random nonce][DptCipher ciphertext]
     *
     * The cipher key is derived per file with HMAC-SHA256(configKey, nonce), so
     * the file layout (version, dex count, method indexes and sizes) is no
     * longer exposed in plaintext. Native side derives the same subkey.
     */
    public static void writeEncryptedMultiDexCode(String out, MultiDexCode multiDexCode, byte[] key) {
        byte[] plain = makeMultiDexCodeBytes(multiDexCode);
        if (plain == null) {
            return;
        }
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("code item key is empty");
        }

        byte[] nonce = new byte[CODE_ITEM_NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);

        byte[] fileKey = CryptoUtils.hmacSha256(key, nonce);
        byte[] cipherText = DptCipher.crypt(fileKey, DptCipher.TWEAK_CODE_ITEM, plain);
        if (cipherText == null || cipherText.length != plain.length) {
            throw new IllegalStateException("encrypt code item failed");
        }

        byte[] outData = new byte[nonce.length + cipherText.length];
        System.arraycopy(nonce, 0, outData, 0, nonce.length);
        System.arraycopy(cipherText, 0, outData, nonce.length, cipherText.length);
        IoUtils.writeFile(out, outData);

        Arrays.fill(plain, (byte) 0);
        Arrays.fill(fileKey, (byte) 0);
    }
}
