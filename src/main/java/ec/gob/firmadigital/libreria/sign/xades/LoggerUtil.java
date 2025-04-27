/*
 * Copyright (C) 2024 
 * Authors: Ricardo Arguello, Misael Fernández
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.*
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package ec.gob.firmadigital.libreria.sign.xades;

import java.util.Arrays;

/**
 * Clase con m&eacute;todos para el trabajo con logs.
 */
public final class LoggerUtil {

    private static Boolean allowExtendedLogs = null;

    private LoggerUtil() {
        // No permitimos la instanciacion
    }

    /**
     * Omite el directorio del usuario por USERHOME.
     *
     * @param path Ruta del directorio a tratar.
     * @return Ruta ofuscada.
     */
    public static String getCleanUserHomePath(final String path) {
        return path.replace(System.getProperty("user.home"), "USERHOME"); //$NON-NLS-1$
    }

    /**
     * Limita la cadena a 200 caracteres. En caso de que la propiedad
     * "allow.extended.logs" est&eacute; activa, se omite el recortarla.
     *
     * @param str Cadena a recortar.
     * @return Cadena tratada.
     */
    public static String getTrimStr(final String str) {
        if (allowExtendedLogs == null) {
            allowExtendedLogs = Boolean.valueOf(Boolean.getBoolean("allow.extended.logs")); //$NON-NLS-1$
        }

        if (!allowExtendedLogs.booleanValue() && str != null && str.length() >= 200) {
            return str.substring(0, 200) + "..."; //$NON-NLS-1$
        }

        return str;
    }

    /**
     * Limita un array de bytes a 200 caracteres. En caso de que la propiedad
     * "allow.extended.logs" est&eacute; activa, se omite el recortarlo.
     *
     * @param content Contenido a recortar.
     * @return Cadena tratada.
     */
    public static String getTrimBytes(final byte[] content) {
        if (allowExtendedLogs == null) {
            allowExtendedLogs = Boolean.valueOf(Boolean.getBoolean("allow.extended.logs")); //$NON-NLS-1$
        }

        if (!allowExtendedLogs.booleanValue() && content != null && content.length > 200) {
            return new String(Arrays.copyOfRange(content, 0, 200)) + "..."; //$NON-NLS-1$
        }

        return new String(content);
    }
}
