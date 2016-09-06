package org.eclipse.che.ide.ui.loaders;

import com.google.inject.assistedinject.Assisted;

import javax.validation.constraints.NotNull;

/**
 * Factory to create instances of PopupLoaderImpl.
 *
 * @author Vitaliy Guliy
 */
public interface PopupLoaderFactory {

    /**
     * Creates an instance of PopupLoaderImpl
     *
     * @param title
     *          loader title
     * @param description
     *          description
     * @return
     *          instance of PopupLoaderImpl
     */
    PopupLoaderImpl getPopup(@NotNull @Assisted("title") String title, @NotNull @Assisted("description") String description);

}
