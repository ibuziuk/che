package org.eclipse.che.workspace.infrastructure.openshift.environment;

import com.google.inject.AbstractModule;
import com.google.inject.multibindings.MapBinder;

public class OpenShiftEnvironmentTypeModule extends AbstractModule {
  @Override
  protected void configure() {
    // Environment type
    MapBinder<String, OpenShiftConfigSourceSpecificEnvironmentParser> envParserMapBinder =
        MapBinder.newMapBinder(
            binder(), String.class, OpenShiftConfigSourceSpecificEnvironmentParser.class);
    envParserMapBinder
        .addBinding(OpenShiftEnvironmentParser.TYPE)
        .to(OpenShiftEnvironmentParser.class);
    envParserMapBinder
        .addBinding(OpenShiftDockerImageEnvironmentParser.TYPE)
        .to(OpenShiftDockerImageEnvironmentParser.class);
  }
}