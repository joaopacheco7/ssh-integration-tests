package com.ssh.integration.tests;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.Properties;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class SshService {

	public static final int SSH_PORT = 8080;

	private final String host;

	private final String user;

	private final Path privateKeyPath;


	public SshService(String host, String user, Path privateKeyPath) {
		this.host = host;
		this.user = user;
		this.privateKeyPath = privateKeyPath;
	}


	public String executeCommand(String command) {
		Session session = null;
		ChannelExec channel = null;
		try {
			JSch jsch = new JSch();
			jsch.addIdentity(privateKeyPath.toAbsolutePath().toString()); // Adds the private key

			session = jsch.getSession(user, host, SSH_PORT);
			session.setPassword("secret");

			// Configuration to prevent authentication errors
			Properties config = new Properties();
			config.put("StrictHostKeyChecking", "no");
			session.setConfig(config);

			session.connect();

			channel = (ChannelExec) session.openChannel("exec");
			channel.setCommand(command);

			InputStream in = channel.getInputStream();
			channel.connect();

			StringBuilder buffer = new StringBuilder();
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
				String line;
				while ((line = reader.readLine()) != null) {
					buffer.append(line).append("\n");
					System.out.println(line); // prints the output
				}
			}

			return buffer.toString();
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalStateException(e);
		} finally {
			if (channel != null) {
				channel.disconnect();
			}
			if (session != null) {
				session.disconnect();
			}
		}
	}

}
