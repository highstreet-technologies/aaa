/*
 * Copyright (c) 2016, 2017 Inocybe Technologies. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.aaa.cli.dmstore;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.opendaylight.aaa.cli.AaaCliAbstractCommand;
import org.opendaylight.aaa.cli.utils.DataStoreUtils;

/**
 * Removes a user.
 *
 * @author mserngawy
 */
@Service
@Command(name = "remove-user", scope = "aaa", description = "Remove user.")
public class RemoveUser extends AaaCliAbstractCommand {


    @Option(name = "-name", aliases = {
            "--userName" }, description = "The user name", required = true, multiValued = false)
    private String userName;

    @Override
    public Object execute() throws Exception {
        if (super.execute() == null) {
            return LOGIN_FAILED_MESS;
        }
        final String usrId = DataStoreUtils.getUserId(identityStore, userName);
        if (usrId == null) {
            return "User does not exist";
        }
        if (identityStore.deleteUser(usrId) == null) {
            return "Failed to delete user " + userName;
        }
        return "User " + userName + "has been deleted.";
    }
}
