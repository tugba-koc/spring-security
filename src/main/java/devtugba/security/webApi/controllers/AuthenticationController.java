package devtugba.security.webApi.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import devtugba.security.business.abstracts.AuthenticationService;
import devtugba.security.business.requests.CreateAuthenticationRequest;
import devtugba.security.business.requests.CreateRegisterRequest;
import devtugba.security.business.responses.GetAuthenticationResponse;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthenticationController {
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    /* @CrossOrigin(exposedHeaders = {"Access-Control-Allow-Origin","Access-Control-Allow-Credentials"}) */
    public ResponseEntity<GetAuthenticationResponse> register(@RequestBody CreateRegisterRequest createRegisterRequest) {
        return ResponseEntity.ok(this.authenticationService.register(createRegisterRequest));
    }

    @PostMapping("/authenticate")
    /* @CrossOrigin(exposedHeaders = {"Access-Control-Allow-Origin","Access-Control-Allow-Credentials"}) */
    public GetAuthenticationResponse authenticate(@RequestBody CreateAuthenticationRequest createAuthenticationRequest) {
        /* return ResponseEntity.ok(this.authenticationService.authenticate(createAuthenticationRequest)); */
        return this.authenticationService.authenticate(createAuthenticationRequest);
    }
}
