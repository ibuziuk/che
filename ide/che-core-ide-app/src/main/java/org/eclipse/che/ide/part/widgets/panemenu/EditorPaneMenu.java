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
package org.eclipse.che.ide.part.widgets.panemenu;

import com.google.inject.ImplementedBy;

import org.eclipse.che.ide.api.mvp.View;

import javax.validation.constraints.NotNull;

/**
 * @author Roman Nikitenko
 */
@ImplementedBy(EditorPaneMenuWidget.class)
public interface EditorPaneMenu extends View<EditorPaneMenu.ActionDelegate> {

    /** Adds given item to pane menu without separator */
    void addItem(@NotNull EditorPaneMenuItem item);

    /**
     * Adds given item to pane menu
     *
     * @param item
     *         item to adding
     * @param isSeparated
     *         a separator will be added when {@code isSeparated} is set as {@code true}
     */
    void addItem(@NotNull EditorPaneMenuItem item, boolean isSeparated);

    /** Removes given item from pane menu */
    void removeItem(@NotNull EditorPaneMenuItem item);

    interface ActionDelegate {

        /** Handle clicking on item */
        void onItemClicked(@NotNull EditorPaneMenuItem item);

        /**
         * Handle clicking on close button
         *
         * @param item
         *         item to close
         */
        void onItemClose(@NotNull EditorPaneMenuItem item);
    }
}
