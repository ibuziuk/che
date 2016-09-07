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

import org.eclipse.che.commons.annotation.Nullable;
import org.eclipse.che.ide.api.parts.EditorTab;
import org.eclipse.che.ide.api.resources.VirtualFile;

import com.google.gwt.event.shared.EventHandler;
import com.google.gwt.event.shared.GwtEvent;

import static org.eclipse.che.ide.api.event.FileEvent.FileOperation.CLOSE;
import static org.eclipse.che.ide.api.event.FileEvent.FileOperation.OPEN;
import static org.eclipse.che.ide.api.event.FileEvent.FileOperation.SAVE;

/**
 * Event that describes the fact that file is going to be opened.
 *
 * @author Nikolay Zamosenchuk
 * @author Artem Zatsarynnyi
 * @author Roman Nikitenko
 */
public class FileEvent extends GwtEvent<FileEvent.FileEventHandler> {

    /** Handles OpenFileEvent */
    public interface FileEventHandler extends EventHandler {
        void onFileOperation(FileEvent event);
    }

    public static Type<FileEventHandler> TYPE = new Type<>();
    private VirtualFile   file;
    private FileOperation fileOperation;
    private EditorTab     tab;
    private boolean       isAbleClosePane;

    /**
     * Creates new {@link FileEvent}.
     *
     * @param file
     *         {@link VirtualFile} that represents an affected file
     * @param fileOperation
     *         file operation
     */
    private FileEvent(VirtualFile file, FileOperation fileOperation) {
        this.file = file;
        this.fileOperation = fileOperation;
    }

    /**
     * Creates new {@link FileEvent} for {@code FileOperation.CLOSE}.
     *
     * @param tab
     *         tab of the file to close
     * @param isAbleClosePane
     *         whether the pane which contains {@code tab} is able to close or not.
     *         Note: it is possible to close the pane when this one doesn't contains editors anymore.
     */
    private FileEvent(EditorTab tab, boolean isAbleClosePane) {
        this(tab.getFile(), CLOSE);
        this.tab = tab;
        this.isAbleClosePane = isAbleClosePane;
    }

    /**
     * Creates a event for {@code FileOperation.OPEN}.
     */
    public static FileEvent createOpenFileEvent(VirtualFile file) {
        return new FileEvent(file, OPEN);
    }

    /**
     * Creates a event for {@code FileOperation.CLOSE}.
     * Note: the pane which contains this {@code tab} will be closed when the pane doesn't contains editors anymore.
     * Use {@link #createCloseFileEvent(EditorTab tab, boolean isAbleClosePane)} to manage this option.
     *
     * @param tab
     *         tab of the file to close
     */
    public static FileEvent createCloseFileEvent(EditorTab tab) {
        return new FileEvent(tab, true);
    }

    /**
     * Creates a event for {@code FileOperation.CLOSE}.
     *
     * @param tab
     *         tab of the file to close
     * @param isAbleClosePane
     *         whether the pane which contains this {@code tab} is able to close or not.
     *         Note: it is possible to close the pane when this one doesn't contains editors anymore.
     */
    public static FileEvent createCloseFileEvent(EditorTab tab, boolean isAbleClosePane) {
        return new FileEvent(tab, isAbleClosePane);
    }

    /**
     * Creates a event for {@code FileOperation.SAVE}.
     */
    public static FileEvent createSaveFileEvent(VirtualFile file) {
        return new FileEvent(file, SAVE);
    }

    /** {@inheritDoc} */
    @Override
    public Type<FileEventHandler> getAssociatedType() {
        return TYPE;
    }

    /** @return {@link VirtualFile} that represents an affected file */
    public VirtualFile getFile() {
        return file;
    }

    /** @return the type of operation performed with file */
    public FileOperation getOperationType() {
        return fileOperation;
    }

    @Nullable
    public EditorTab getEditorTab() {
        return tab;
    }

    /** Indicates whether the pane which contains this editor is able to close or not. */
    public boolean isAbleClosePane() {
        return isAbleClosePane;
    }

    @Override
    protected void dispatch(FileEventHandler handler) {
        handler.onFileOperation(this);
    }

    public enum FileOperation {
        OPEN, SAVE, CLOSE
    }
}
