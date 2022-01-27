package io.siggi.simplekeyserialization;

import io.siggi.simpleder.DERData;
import io.siggi.simpleder.DERList;
import io.siggi.simpleder.DERParser;
import java.util.Base64;

public class SimpleKeySerialization {

	// <editor-fold desc="PEM" defaultstate="collapsed">
	public static String encodePEM(byte[] data, String dataType) {
		StringBuilder sb = new StringBuilder();
		if (dataType != null) {
			if (dataType.contains("\n") || dataType.contains("\r")) {
				throw new IllegalArgumentException("dataType cannot contain newlines!");
			}
			sb.append("-----BEGIN ").append(dataType).append("-----\n");}
		String encoded = Base64.getEncoder().encodeToString(data);
		int offset = 0;
		while (offset < encoded.length()) {
			int remaining = encoded.length() - offset;
			if (remaining < 64) {
				sb.append(encoded, offset, encoded.length()).append("\n");
				offset = remaining;
			} else {
				sb.append(encoded, offset, offset + 64).append("\n");
				offset += 64;
			}
		}
		sb.append("-----END ").append(dataType).append("-----\n");
		return sb.toString();
	}

	public static byte[] decodePEM(String string) {
		String[] pieces = string.replace("\r", "\n").replaceAll("\n{1,}", "\n").trim().split("\n");
		StringBuilder sb = new StringBuilder();
		for (String piece : pieces) {
			if (piece.startsWith("-")) {
				continue;
			}
			sb.append(piece);
		}
		return Base64.getDecoder().decode(sb.toString());
	}
	// </editor-fold>

	// <editor-fold desc="ECDSA" defaultstate="collapsed">
	public static byte[] encodeECDSAPublicKey(byte[] publicKey) {
		byte[] publicKeyWith0Prefix = new byte[publicKey.length + 1];
		System.arraycopy(publicKey, 0, publicKeyWith0Prefix, 1, publicKey.length);

		DERList list = new DERList();
		DERList subList = new DERList();
		list.items.add(subList);
		subList.items.add(new DERData(6, new byte[]{(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01}));
		subList.items.add(new DERData(6, new byte[]{(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07}));
		list.items.add(new DERData(3, publicKeyWith0Prefix));
		return list.getEncoded();
	}

	public static byte[] encodeECDSAPrivateKey(byte[] privateKey, byte[] publicKey) {
		byte[] publicKeyWith0Prefix = new byte[publicKey.length + 1];
		System.arraycopy(publicKey, 0, publicKeyWith0Prefix, 1, publicKey.length);

		DERList list = new DERList();
		list.items.add(new DERData(2, new byte[]{(byte) 0x0}));
		DERList subList = new DERList();
		list.items.add(subList);
		subList.items.add(new DERData(6, new byte[]{(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01}));
		subList.items.add(new DERData(6, new byte[]{(byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07}));
		DERList keyInfo = new DERList(0x4);
		list.items.add(keyInfo);
		DERList privateKeyInfo = new DERList();
		keyInfo.items.add(privateKeyInfo);
		privateKeyInfo.items.add(new DERData(2, new byte[]{(byte) 0x1}));
		privateKeyInfo.items.add(new DERData(4, privateKey));
		DERList publicKeyInfo = new DERList(0xa1);
		privateKeyInfo.items.add(publicKeyInfo);
		publicKeyInfo.items.add(new DERData(3, publicKeyWith0Prefix));
		return list.getEncoded();
	}

	public static byte[] decodeECDSAPublicKey(byte[] derEncodedKey) {
		try {
			DERList list = DERParser.parse(derEncodedKey);
			byte[] publicKeyWith0Prefix = list.items.get(1).getData();
			byte[] publicKey = new byte[publicKeyWith0Prefix.length-1];
			System.arraycopy(publicKeyWith0Prefix, 1, publicKey, 0, publicKey.length);
			return publicKey;
		} catch (Exception e) {
			return null;
		}
	}

	public static byte[] decodeECDSAPrivateKey(byte[] derEncodedKey) {
		try {
			DERList list = DERParser.parse(derEncodedKey);
			return ((DERList) (((DERList) list.items.get(2)).items.get(0))).items.get(1).getData();
		} catch (Exception e) {
			return null;
		}
	}
	// </editor-fold>
}
