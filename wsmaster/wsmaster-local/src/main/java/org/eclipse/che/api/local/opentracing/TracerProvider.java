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
package org.eclipse.che.api.local.opentracing;

import brave.Tracing;
import brave.opentracing.BraveTracer;
import brave.propagation.B3Propagation;
import brave.propagation.ExtraFieldPropagation;
import brave.propagation.Propagation.Factory;
import io.opentracing.Tracer;
import java.util.Arrays;
import javax.annotation.PostConstruct;
import javax.inject.Singleton;
import zipkin2.Span;
import zipkin2.codec.SpanBytesEncoder;
import zipkin2.reporter.AsyncReporter;
import zipkin2.reporter.okhttp3.OkHttpSender;

@Singleton
public class TracerProvider {
  private static final String SERVICE_NAME = "wsmaster-local-injects";
  private Tracer tracer;

  @PostConstruct
  private void init() {
    OkHttpSender sender =
        OkHttpSender.create("http://zipkin-zipkin.192.168.42.143.nip.io/api/v1/spans");
    AsyncReporter<Span> spanReporter =
        AsyncReporter.builder(sender).build(SpanBytesEncoder.JSON_V1);

    Factory propagationFactory =
        ExtraFieldPropagation.newFactoryBuilder(B3Propagation.FACTORY)
            .addPrefixedFields("baggage-", Arrays.asList("country-code", "user-id"))
            .build();

    Tracing braveTracing =
        Tracing.newBuilder()
            .localServiceName(SERVICE_NAME)
            .propagationFactory(propagationFactory)
            .spanReporter(spanReporter)
            .build();
    this.tracer = BraveTracer.create(braveTracing);
  }

  public Tracer getTracer() {
    return this.tracer;
  }
}
