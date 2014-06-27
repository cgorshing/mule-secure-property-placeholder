package com.example

import org.bouncycastle.util.encoders.Base64
import org.junit.Test
import org.mule.security.encryption.binary.jce.algorithms.EncryptionAlgorithm
import org.mule.security.encryption.binary.jce.algorithms.EncryptionMode

class EncryptionDecryptionTest {
  //16 bytes is the largest
  private static final String KEY = '!@#$%^()!@#$!@#$'

  @Test
  void goBothWays() {

    EncryptionAlgorithm algo = EncryptionAlgorithm.AES;

    assert '52ZsPUJRX4Blw5VctpDxbM71vTqGCmuH+uZ1ke5KsDs=' == new String(Base64.encode(algo.getBuilder().
            using(EncryptionMode.CBC).
            forKey(KEY).
            build().encrypt('super.secret.password'.bytes)))

    assert 'super.secret.password' == new String(algo.getBuilder().
            using(EncryptionMode.CBC).
            forKey(KEY).
            build().decrypt(Base64.decode('52ZsPUJRX4Blw5VctpDxbM71vTqGCmuH+uZ1ke5KsDs=')))
  }
}
