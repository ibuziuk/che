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
package org.eclipse.che.ide.api.event;

import com.google.gwt.event.shared.GwtEvent;

import org.eclipse.che.ide.api.parts.PartPresenter;
import org.eclipse.che.ide.api.parts.PartStack;

/**
 * Event that notifies of changing active PartPresenter
 *
 * @author Nikolay Zamosenchuk
 */
public class ActivePartChangedEvent extends GwtEvent<ActivePartChangedHandler> {
    public static Type<ActivePartChangedHandler> TYPE = new Type<>();

    private final PartPresenter activePart;
    private final PartStack     activePartStack;

    public ActivePartChangedEvent(PartPresenter activePart, PartStack activePartStack) {
        this.activePart = activePart;
        this.activePartStack = activePartStack;
    }

    @Override
    public Type<ActivePartChangedHandler> getAssociatedType() {
        return TYPE;
    }

    /** @return instance of Active Part */
    public PartPresenter getActivePart() {
        return activePart;
    }

    /** @return instance of Active Part Stack */
    public PartStack getActivePartStack() {
        return activePartStack;
    }

    @Override
    protected void dispatch(ActivePartChangedHandler handler) {
        handler.onActivePartChanged(this);
    }
}
