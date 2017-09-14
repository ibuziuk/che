/*
 * Copyright (c) 2012-2017 Red Hat, Inc.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Red Hat, Inc. - initial API and implementation
 */
package org.eclipse.che.api.workspace.server;

import org.eclipse.che.api.core.model.workspace.runtime.RuntimeIdentity;
import org.eclipse.che.api.workspace.server.spi.InfrastructureException;
import org.eclipse.che.commons.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * System specific strategy for rewriting URLs to use in rewriting Servers, Hyperlinks, etc For
 * example in a case when machines supposed to be accessible via reverse Proxy.
 *
 * @author gazarenkov
 */
public interface URLRewriter {
  Logger LOG = LoggerFactory.getLogger(URLRewriter.class);
  /**
   * Rewrites URL according to URL rewriting strategy rules. May depend on
   * RuntimeIdentityImpl(workspace, owner,..) and name (some id) of this particular URL
   *
   * @param identity RuntimeIdentityImpl
   * @param name symbolic name of the server
   * @param url URL to rewrite
   * @return rewritten URL (may be unchanged)
   * @throws InfrastructureException if URL rewriting failed
   */
  String rewriteURL(@Nullable RuntimeIdentity identity, @Nullable String name, String url)
      throws InfrastructureException;

  /** No rewriting, just pass URL back */
  class NoOpURLRewriter implements URLRewriter {
    @Override
    public String rewriteURL(@Nullable RuntimeIdentity identity, @Nullable String name, String url)
        throws InfrastructureException {

      if (url.startsWith("ws:")) {
        LOG.info("URL before modification {}", url);
        url = url.replaceFirst("^ws", "wss");
        LOG.info("URL after modification {}", url);
        return url;
      } else if (url.startsWith("http:")) {
        LOG.info("URL before modification {}", url);
        url = url.replaceFirst("^http", "https");
        LOG.info("URL after modification {}", url);
        return url;
      }

      return url;
    }
  }
}
