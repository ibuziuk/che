/*******************************************************************************
 * Copyright (c) 2012-2016 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package org.eclipse.che.ide.ui.loaders;

import com.google.inject.Inject;
import com.google.inject.Singleton;

import java.util.HashMap;
import java.util.Map;

/**
 * Manages loaders for loading phases.
 *
 * @author Vitaliy Guliy
 */
@Singleton
public class LoaderPresenter {

    public enum Phase {

        STARTING_WORKSPACE_RUNTIME("Starting workspace runtime", "Retrieving the stack's image and launching it"),
        STARTING_WORKSPACE_AGENT("Starting workspace agent", "Agent provides RESTful services like intellisense and SSH"),
        CREATING_PROJECT("Creating project", "Creating and configuring a project");

        private final String title;
        private final String description;

        Phase(String title, String description) {
            this.title = title;
            this.description = description;
        }

        public String getTitle() {
            return title;
        }

        public String getDescription() {
            return description;
        }
    }

    public enum Status {

        LOADING,
        SUCCESS,
        ERROR;

    }

    private PopupLoaderFactory popupLoaderFactory;

    private Map<Phase, PopupLoader> popups = new HashMap<>();

    @Inject
    public LoaderPresenter(PopupLoaderFactory popupLoaderFactory) {
        this.popupLoaderFactory = popupLoaderFactory;
    }

    /**
     * Sets phase and status.
     *
     * @param phase
     *          phase
     * @param status
     *          status
     */
    public void setProgress(Phase phase, Status status) {
        PopupLoader popup = popups.get(phase);

        if (popup == null) {
            // Create and show a loader
            popup = popupLoaderFactory.getPopup(phase.getTitle(), phase.getDescription());
            popups.put(phase, popup);

        } else if (Status.SUCCESS == status) {
            // Hide the loader if status is SUCCESS
            popups.remove(phase);
            popup.setSuccess();

        } else if (Status.ERROR == status) {
            // Don't hide the loader with status ERROR
            popups.remove(phase);
            popup.setError();
        }
    }

}
