/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Set of inhibited cryptography algorithms.
 */
public class CryptographyInitializeConfiguration {

	private static Set<String> INHIBIT = new HashSet<>();

	static {
		String algorithms = StringUtil.getConfiguration("INHIBIT_ALGORITHMS");
		if (algorithms != null) {
			for (String algorithm : algorithms.split(",")) {
				inhibit(algorithm);
			}
		}
	}

	public static void inhibit(String algorithm) {
		INHIBIT.add(algorithm.toLowerCase());
	}

	public static void inhibit(String algorithm, String... more) {
		inhibit(algorithm);
		if (more != null) {
			for (String algo : more) {
				inhibit(algo);
			}
		}
	}

	public static boolean isInhibited(String algorithm) {
		return algorithm == null || INHIBIT.contains(algorithm.toLowerCase());
	}
}
