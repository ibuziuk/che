package org.eclipse.che.workspace.infrastructure.openshift.environment;

import org.eclipse.che.api.core.ValidationException;
import org.eclipse.che.api.workspace.server.spi.InfrastructureException;
import org.eclipse.che.api.workspace.server.spi.InternalEnvironment;
import org.eclipse.che.api.workspace.server.spi.InternalEnvironment.InternalRecipe;

public class OpenShiftDockerImageEnvironmentParser implements OpenShiftConfigSourceSpecificEnvironmentParser{
    public static final String TYPE = "dockerimage";

    @Override
    public OpenShiftEnvironment parse(InternalEnvironment environment)
            throws ValidationException, InfrastructureException {
        InternalRecipe recipe = environment.getRecipe();
        String contentType = recipe.getContentType();

        return null;
    }

}
