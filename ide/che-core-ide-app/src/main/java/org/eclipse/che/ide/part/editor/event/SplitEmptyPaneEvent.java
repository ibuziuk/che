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

import org.eclipse.che.ide.api.constraints.Direction;
import org.eclipse.che.ide.api.parts.EditorPartStack;

/**
 * Event to split a pane which not contains any opened editors.
 *
 * @author Roman Nikitenko
 */
public class SplitEmptyPaneEvent extends GwtEvent<SplitEmptyPaneEvent.SplitEmptyPaneHandler> {

    public interface SplitEmptyPaneHandler extends EventHandler {
        void onSplitEmptyPane(SplitEmptyPaneEvent event);
    }

    private static Type<SplitEmptyPaneHandler> TYPE;

    public static Type<SplitEmptyPaneHandler> getType() {
        if (TYPE == null) {
            TYPE = new Type<>();
        }
        return TYPE;
    }

    private final Direction       direction;
    private final EditorPartStack editorPartStack;

    /**
     * Creates new {@link SplitEmptyPaneEvent}
     *
     * @param editorPartStack
     *         pane to splitting
     * @param direction
     *         direction type that specifies the way of splitting(horizontally or vertically)
     */
    public SplitEmptyPaneEvent(Direction direction, EditorPartStack editorPartStack) {
        this.direction = direction;
        this.editorPartStack = editorPartStack;
    }

    /** Returns the way of splitting(horizontally or vertically) */
    public Direction getDirection() {
        return direction;
    }

    /** Returns pane to splitting */
    public EditorPartStack getPaneToSplitting() {
        return editorPartStack;
    }

    /** {@inheritDoc} */
    @Override
    public Type<SplitEmptyPaneHandler> getAssociatedType() {
        return getType();
    }

    /** {@inheritDoc} */
    @Override
    protected void dispatch(SplitEmptyPaneHandler handler) {
        handler.onSplitEmptyPane(this);
    }
}
