package devtugba.security.business.abstracts;

import devtugba.security.business.requests.CreateAuthenticationRequest;
import devtugba.security.business.requests.CreateRegisterRequest;
import devtugba.security.business.responses.GetAuthenticationResponse;

public interface AuthenticationService {
    GetAuthenticationResponse register(CreateRegisterRequest createRegisterRequest);
    GetAuthenticationResponse authenticate(CreateAuthenticationRequest createAuthenticationRequest);
}
