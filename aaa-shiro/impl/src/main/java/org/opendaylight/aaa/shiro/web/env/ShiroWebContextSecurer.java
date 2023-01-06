/*
 * Copyright (c) 2018 Red Hat, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.aaa.shiro.web.env;

import static java.util.Objects.requireNonNull;

import org.apache.shiro.web.env.WebEnvironment;
import org.opendaylight.aaa.shiro.filters.AAAShiroFilter;
import org.opendaylight.aaa.web.FilterDetails;
import org.opendaylight.aaa.web.WebContext;
import org.opendaylight.aaa.web.WebContextBuilder;
import org.opendaylight.aaa.web.WebContextSecurer;

/**
 * Secures a {@link WebContext} using Shiro.
 *
 * @author Michael Vorburger.ch
 */
public class ShiroWebContextSecurer implements WebContextSecurer {
    private final WebEnvironment webEnvironment;

    public ShiroWebContextSecurer(final WebEnvironment webEnvironment) {
        this.webEnvironment = requireNonNull(webEnvironment);
    }

    @Override
    public void requireAuthentication(final WebContextBuilder webContextBuilder, final boolean asyncSupported,
            final String... urlPatterns) {
        webContextBuilder
            // AAA filter in front of these REST web services as well as for moon endpoints
            .addFilter(FilterDetails.builder()
                .filter(new AAAShiroFilter(webEnvironment))
                .addUrlPatterns(urlPatterns)
                .asyncSupported(asyncSupported)
                .build());
    }
}
