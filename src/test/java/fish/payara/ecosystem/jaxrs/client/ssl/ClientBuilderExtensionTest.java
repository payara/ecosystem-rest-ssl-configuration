/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) [2021] Payara Foundation and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://github.com/payara/Payara/blob/master/LICENSE.txt
 * See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * The Payara Foundation designates this particular file as subject to the "Classpath"
 * exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package fish.payara.ecosystem.jaxrs.client.ssl;

import fish.payara.security.client.PayaraConstants;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.ws.rs.client.Client;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class ClientBuilderExtensionTest {

    @Mock
    private JerseyClientBuilder jerseyClientBuilder;

    @Mock
    private ClientConfig clientConfig;

    @Mock
    private JerseyClient jerseyClient;

    @InjectMocks
    @Spy
    private ClientBuilderExtension clientBuilderExtension = new ClientBuilderExtension();

    @Test
    public void clientBuilderExtensionSetPropertyTest() throws Exception {
        KeyManager[] managers = getManagers();
        KeyStore[] keyStores = new KeyStore[]{getKeyStore()};

        when(jerseyClientBuilder.getConfiguration()).thenReturn(clientConfig);
        when(clientConfig.getProperty(PayaraConstants.JAXRS_CLIENT_CERTIFICATE_ALIAS)).thenReturn("myKey");
        when(jerseyClientBuilder.build()).thenReturn(jerseyClient);
        doReturn(managers).when(clientBuilderExtension).getKeyManagers();
        doReturn(keyStores).when(clientBuilderExtension).getKeyStores();

        Client client = clientBuilderExtension.property(PayaraConstants.JAXRS_CLIENT_CERTIFICATE_ALIAS, "myKey").build();

        assertNotNull(client);
        verify(clientBuilderExtension, times(1)).evaluateAliasProperty();
        verify(clientBuilderExtension, times(1)).buildSSlContext(anyString());
        verify(clientBuilderExtension, times(1)).getKeyManagers();
        verify(clientBuilderExtension, times(1)).getKeyStores();
    }

    @Test
    public void clientBuilderExtensionWithoutPropertyTest() {
        when(jerseyClientBuilder.getConfiguration()).thenReturn(clientConfig);
        when(clientConfig.getProperty(PayaraConstants.JAXRS_CLIENT_CERTIFICATE_ALIAS)).thenReturn(null);
        when(jerseyClientBuilder.build()).thenReturn(jerseyClient);

        Client client = clientBuilderExtension.property(PayaraConstants.JAXRS_CLIENT_CERTIFICATE_ALIAS, "myKey").build();

        assertNotNull(client);
        verify(clientBuilderExtension, times(1)).evaluateAliasProperty();
    }

    public KeyStore getKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, URISyntaxException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        URL resource = getClass().getClassLoader().getResource("keystore.jks");
        FileInputStream keyStoreFile = new FileInputStream(new File(resource.toURI()));
        keyStore.load(keyStoreFile, "changeit".toCharArray());
        return keyStore;
    }

    public KeyManager[] getManagers() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, URISyntaxException {
        KeyStore keyStore = getKeyStore();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeit".toCharArray());
        return kmf.getKeyManagers();
    }
}