/*
 * Copyright © 2018 Inocybe Technologies and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.aaa.authenticator;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.Subject;
import org.jolokia.osgi.security.Authenticator;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AAA hook for <code>odl-jolokia</code> configured w/ <code>org.jolokia.authMode=service-all</code>.
 */
@Singleton
@Component(immediate = true)
public class ODLAuthenticator implements Authenticator {
    private static final Logger LOG = LoggerFactory.getLogger(ODLAuthenticator.class);

    @Inject
    public ODLAuthenticator() {
        // Exposed for DI
    }

    @Override
    public boolean authenticate(final HttpServletRequest httpServletRequest) {
        final String authorization = httpServletRequest.getHeader("Authorization");

        LOG.trace("Incoming Jolokia authentication attempt: {}", authorization);

        if (authorization == null || !authorization.startsWith("Basic")) {
            return false;
        }

        try {
            final String base64Creds = authorization.substring("Basic".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Creds), StandardCharsets.UTF_8);
            final String[] values = credentials.split(":", 2);
            UsernamePasswordToken upt = new UsernamePasswordToken();
            upt.setUsername(values[0]);
            upt.setPassword(values[1].toCharArray());

            try {
                return login(upt);
            } catch (UnknownSessionException e) {
                LOG.debug("Couldn't log in {} - logging out and retrying...", upt, e);
                logout();
                return login(upt);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // FIXME: who throws this above and why do we need to catch it? Should this be error or warn?
            LOG.trace("Formatting issue with basic auth credentials: {}", authorization, e);
        }

        return false;
    }

    private static void logout() {
        final Subject subject = SecurityUtils.getSubject();
        try {
            subject.logout();
            Session session = subject.getSession(false);
            if (session != null) {
                session.stop();
            }
        } catch (ShiroException e) {
            LOG.debug("Couldn't log out {}", subject, e);
        }
    }

    private static boolean login(final UsernamePasswordToken upt) {
        final Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(upt);
        } catch (AuthenticationException e) {
            LOG.trace("Couldn't authenticate the subject: {}", subject, e);
            return false;
        }
        return true;
    }
}
