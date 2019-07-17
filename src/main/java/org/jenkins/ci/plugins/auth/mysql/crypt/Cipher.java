/**
 * The person or persons who have associated work with this document (the
 * "Dedicator" or "Certifier") hereby either (a) certifies that, to the best of
 * his knowledge, the work of authorship identified is in the public domain of
 * the country from which the work is published, or (b) hereby dedicates
 * whatever copyright the dedicators holds in the work of authorship identified
 * below (the "Work") to the public domain. A certifier, moreover, dedicates any
 * copyright interest he may have in the associated work, and for these
 * purposes, is described as a "dedicator" below.
 * <p>
 * A certifier has taken reasonable steps to verify the copyright status of this
 * work. Certifier recognizes that his good faith efforts may not shield him
 * from liability if in fact the work certified is not in the public domain.
 * <p>
 * Dedicator makes this dedication for the benefit of the public at large and to
 * the detriment of the Dedicator's heirs and successors. Dedicator intends this
 * dedication to be an overt act of relinquishment in perpetuity of all present
 * and future rights under copyright law, whether vested or contingent, in the
 * Work. Dedicator understands that such relinquishment of all rights includes
 * the relinquishment of all rights to enforce (by lawsuit or otherwise) those
 * copyrights in the Work.
 * <p>
 * Dedicator recognizes that, once placed in the public domain, the Work may be
 * freely reproduced, distributed, transmitted, used, modified, built upon, or
 * otherwise exploited by anyone for any purpose, commercial or non-commercial,
 * and in any way, including by methods that have not yet been invented or
 * conceived.
 */
package org.jenkins.ci.plugins.auth.mysql.crypt;

import hudson.Util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class produces an encrypted string based upon the selected cipher or
 * digest method.
 *
 * @author Alex Ackerman
 */
public class Cipher {
    /**
     * Digest algorithm names from the Java Cruptography Architecture Standard
     * Algorithm Name Documentation found at the following address:
     *
     * http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html
     *
     */
    public static final String MD5 = "MD5";
    public static final String SHA1 = "SHA-1";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";
    public static final String CRYPT = "Crypt";


    public Cipher(String type) {
        this.encryptionMethod = type;
        salt = null;
    }

    public Cipher(String type, String salt) {
        this.encryptionMethod = type;
        this.salt = salt;
    }

    public String encode(String plaintext,int hashTimes) throws EncryptionException {
//        if ((salt != null) || encryptionMethod.equals(this.CRYPT)) {
//            return JCrypt.crypt(salt, plaintext);
//        } else {
            try {
                MessageDigest md = MessageDigest.getInstance(encryptionMethod);
                md.reset();
                if(salt != null && !"".equals(salt.trim())){
                    md.update(salt.getBytes());
                }
                byte[] textBytes = plaintext.getBytes();
                // 摘要更新之后，通过调用digest（）执行哈希计算，获得密文
                byte[] hash = md.digest(textBytes);

                for(int i = 1;i < hashTimes;i++){
                    md.reset();
                    hash = md.digest(hash);
                }

                return Util.toHexString(hash);
            } catch (NoSuchAlgorithmException ex) {
                throw new EncryptionException();
            }
//        }
    }

    private String encryptionMethod;
    private String salt;
}
