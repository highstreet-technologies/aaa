package org.opendaylight.aaa.shiro.oauth;

import com.google.common.collect.ImmutableSet;
import java.io.IOException;
import java.util.Set;
import javax.ws.rs.core.Application;
import org.opendaylight.aaa.shiro.oauth.data.InvalidConfigurationException;
import org.opendaylight.aaa.shiro.oauth.data.UnableToConfigureOAuthService;
import org.opendaylight.aaa.shiro.oauth.http.AuthHttpHandler;

public class OAuthApplication extends Application {

    @Override
    public Set<Object> getSingletons() {
        try {
            return ImmutableSet.of(
                    new AuthHttpHandler(null, null, null, null)
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidConfigurationException e) {
            throw new RuntimeException(e);
        } catch (UnableToConfigureOAuthService e) {
            throw new RuntimeException(e);
        }
    }
}
