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
package org.eclipse.che.workspace.infrastructure.openshift.environment;

import static java.lang.String.format;

import java.util.Map;

import javax.inject.Inject;

import org.eclipse.che.api.core.ValidationException;
import org.eclipse.che.api.workspace.server.spi.InfrastructureException;
import org.eclipse.che.api.workspace.server.spi.InternalEnvironment;
import org.eclipse.che.api.workspace.server.spi.InternalEnvironment.InternalRecipe;

import com.google.common.base.Joiner;

public class EnvironmentParser {
    private final Map<String, OpenShiftConfigSourceSpecificEnvironmentParser> environmentParsers;

    @Inject
    public EnvironmentParser(Map<String, OpenShiftConfigSourceSpecificEnvironmentParser> environmentParsers) {
        this.environmentParsers = environmentParsers;
    }

    public OpenShiftEnvironment parse(InternalEnvironment environment)
            throws ValidationException, InfrastructureException {

        InternalRecipe recipe = environment.getRecipe();

        OpenShiftConfigSourceSpecificEnvironmentParser parser = environmentParsers.get(recipe.getType());
        if (parser == null) {
            throw new ValidationException(
                    format("Environment type '%s' is not supported. " + "Supported environment types: %s",
                            recipe.getType(), Joiner.on(", ").join(environmentParsers.keySet())));
        }

        OpenShiftEnvironment openShiftEnvironment = parser.parse(environment);

        return openShiftEnvironment;
    }

}
