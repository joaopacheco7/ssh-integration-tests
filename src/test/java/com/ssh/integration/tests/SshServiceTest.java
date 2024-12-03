package com.ssh.integration.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.jcraft.jsch.JSchException;

import base.SshKeyGenerator;

class SshServiceTest {

	private static final Path TEMP_DIR = Paths.get(System.getProperty("java.io.tmpdir"));

	private static final int SSH_PORT = 8080;

	private static final String VALID_USER = "jpacheco";

	private static SshServer SSHD;

	private static SshKeyGenerator.TempKeyPair SSH_KEYS;


	@BeforeAll
	public static void startSshServer() throws IOException {
		SSHD = SshServer.setUpDefaultServer();
		SSHD.setPort(SSH_PORT);
		SSHD.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(TEMP_DIR.resolve("hostkey.ser")));
		SSHD.setPasswordAuthenticator((username, password, session) -> VALID_USER.equals(username)); // auth via password
		SSHD.setPublickeyAuthenticator((username, key, session) -> VALID_USER.equals(username)); // auth via private key
		SSHD.setCommandFactory(new ProcessShellCommandFactory());
		SSHD.start();

		// creates a temporary pair of public and private keys
		SSH_KEYS = new SshKeyGenerator().createTempKeys();
	}


	@AfterAll
	public static void stopSshServer() throws IOException {
		if (SSHD != null) {
			SSHD.stop();
		}
	}


	@Test
	@DisplayName("Should execute a remote command via SSH")
	void t1() {
		// scenario
		Path privatePath = SSH_KEYS.privateKey();
		SshService service = new SshService("localhost", VALID_USER, privatePath);

		// action
		String result = service.executeCommand("echo 'Hello World!'");

		// validation
		assertThat(result).contains("Hello World!");
	}


	@Test
	@DisplayName("Should not execute a remote command via SSH when credentials are invalid")
	void t2() {
		// scenario
		Path privatePath = SSH_KEYS.privateKey();
		SshService service = new SshService("localhost", "invalid-user", privatePath);

		// action & validation
		assertThatThrownBy(() -> {
			service.executeCommand("echo 'This should not work.'");
		}).hasRootCauseInstanceOf(JSchException.class).hasMessageContaining("Auth fail");
	}


	@Test
	@DisplayName("Should not execute a remote command via SSH when private key is not found")
	void t3() {
		// scenario
		Path nonExistingPrivateKey = TEMP_DIR.resolve("non-existing-private_key.pem");
		SshService service = new SshService("localhost", VALID_USER, nonExistingPrivateKey);

		// action & validation
		assertThatThrownBy(() -> {
			service.executeCommand("echo 'This should not work.'");
		}).hasRootCauseInstanceOf(FileNotFoundException.class).hasMessageContaining("non-existing-private_key.pem");
	}


	@Test
	@DisplayName("Should not execute a remote command via SSH when private key is invalid")
	void t4() throws IOException {
		// scenario
		Path invalidPrivateKey = Files.createTempFile("private_key", ".pem");
		SshService service = new SshService("localhost", VALID_USER, invalidPrivateKey);

		// action & validation
		assertThatThrownBy(() -> {
			service.executeCommand("echo 'This should not work.'");
		}).hasRootCauseInstanceOf(JSchException.class).hasMessageContaining("invalid privatekey");
	}

}
