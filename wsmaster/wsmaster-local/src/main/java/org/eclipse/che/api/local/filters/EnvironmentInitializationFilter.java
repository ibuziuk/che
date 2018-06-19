/*
 * Copyright (c) 2012-2018 Red Hat, Inc.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Red Hat, Inc. - initial API and implementation
 */
package org.eclipse.che.api.local.filters;

import io.opentracing.Scope;
import io.opentracing.Span;
import io.opentracing.log.Fields;
import io.opentracing.propagation.Format;
import io.opentracing.propagation.TextMapExtractAdapter;
import io.opentracing.propagation.TextMapInjectAdapter;
import io.opentracing.tag.StringTag;
import io.opentracing.tag.Tags;
import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;
import org.eclipse.che.api.local.opentracing.TracerProvider;
import org.eclipse.che.commons.env.EnvironmentContext;
import org.eclipse.che.commons.subject.Subject;
import org.eclipse.che.commons.subject.SubjectImpl;

/**
 * Fills environment context with information about current subject.
 *
 * @author Dmitry Shnurenko
 */
@Singleton
public class EnvironmentInitializationFilter implements Filter {
  private static final String REQUEST_ID_HEADER = "X-Request-Id";

  @Inject TracerProvider tracerProvider;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {}

  @Override
  public final void doFilter(
      ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {
    String url = ((HttpServletRequest) request).getRequestURL().toString();
    Map<String, String> headers = getHeaders((HttpServletRequest) request);
    String requestId = ((HttpServletRequest) request).getHeader(REQUEST_ID_HEADER);

    Span span =
        tracerProvider
            .getTracer()
            .buildSpan(url)
            .asChildOf(
                tracerProvider
                    .getTracer()
                    .extract(Format.Builtin.HTTP_HEADERS, new TextMapExtractAdapter(headers)))
            .withTag("description", "in wsmaster local")
            .start();
    try (Scope scope = tracerProvider.getTracer().scopeManager().activate(span, false)) {

      final HttpServletRequest httpRequest = (HttpServletRequest) request;
      Subject subject = new SubjectImpl("che", "che", "dummy_token", false);
      HttpSession session = httpRequest.getSession();
      session.setAttribute("codenvy_user", subject);

      if (scope != null) {
        StringTag identityIdTag = new StringTag("Subject");
        identityIdTag.set(scope.span(), subject.getUserId());

        StringTag requestIdTag = new StringTag("req_id");
        if (requestId != null) {
          requestIdTag.set(scope.span(), requestId);
        } else {
          requestIdTag.set(scope.span(), "unknown");
        }
      }

      final EnvironmentContext environmentContext = EnvironmentContext.getCurrent();

      environmentContext.setSubject(subject);
      tracerProvider
          .getTracer()
          .inject(
              scope.span().context(),
              Format.Builtin.HTTP_HEADERS,
              new TextMapInjectAdapter(headers));
      filterChain.doFilter(addUserInRequest(httpRequest, subject), response);
    } catch (Exception e) {
      Tags.ERROR.set(span, true);
      Map map = new HashMap<>();
      map.put(Fields.EVENT, "error");
      map.put(Fields.ERROR_OBJECT, e);
      map.put(Fields.MESSAGE, e.getMessage());
      span.log(map);
      throw e;
    } finally {
      EnvironmentContext.reset();
      span.finish();
    }
  }

  private HttpServletRequest addUserInRequest(
      final HttpServletRequest httpRequest, final Subject subject) {
    return new HttpServletRequestWrapper(httpRequest) {
      @Override
      public String getRemoteUser() {
        return subject.getUserName();
      }

      @Override
      public Principal getUserPrincipal() {
        return () -> subject.getUserName();
      }
    };
  }

  @Override
  public void destroy() {}

  private Map<String, String> getHeaders(HttpServletRequest request) {

    Map<String, String> map = new HashMap<String, String>();

    Enumeration headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String key = (String) headerNames.nextElement();
      String value = request.getHeader(key);
      map.put(key, value);
    }

    return map;
  }
}
