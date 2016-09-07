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
package org.eclipse.che.ide.part.editor.event;

import com.google.gwt.event.shared.EventHandler;
import com.google.gwt.event.shared.GwtEvent;

import org.eclipse.che.ide.api.parts.EditorPartStack;
import org.eclipse.che.ide.util.loging.Log;

/**
 * Close current pane event.
 * Note: the pane will not be closed when pane contains at least one opened editor.
 *
 * @author Roman Nikitenko
 */
public class ClosePaneEvent extends GwtEvent<ClosePaneEvent.ClosePaneHandler> {

    public interface ClosePaneHandler extends EventHandler {
        void onClosePane(ClosePaneEvent event);
    }

    private static Type<ClosePaneHandler> TYPE;

    public static Type<ClosePaneHandler> getType() {
        if (TYPE == null) {
            TYPE = new Type<>();
        }
        return TYPE;
    }

    private final EditorPartStack editorPartStack;

    /**
     * Creates new {@link ClosePaneEvent}
     *
     * @param editorPartStack
     *         pane to close
     */
    public ClosePaneEvent(EditorPartStack editorPartStack) {
        Log.error(getClass(), "ClosePaneEvent constructor");
        this.editorPartStack = editorPartStack;
    }

    public EditorPartStack getEditorPartStack() {
        return editorPartStack;
    }

    /** {@inheritDoc} */
    @Override
    public Type<ClosePaneHandler> getAssociatedType() {
        return getType();
    }

    /** {@inheritDoc} */
    @Override
    protected void dispatch(ClosePaneHandler handler) {
        handler.onClosePane(this);
    }
}
