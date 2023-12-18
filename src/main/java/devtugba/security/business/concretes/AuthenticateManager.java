package devtugba.security.business.concretes;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import devtugba.security.business.abstracts.AuthenticationService;
import devtugba.security.business.requests.CreateAuthenticationRequest;
import devtugba.security.business.requests.CreateRegisterRequest;
import devtugba.security.business.responses.GetAuthenticationResponse;
import devtugba.security.config.concretes.JwtManager;
import devtugba.security.constants.Role;
import devtugba.security.dataAccess.abstracts.UserRepository;
import devtugba.security.entities.concretes.User;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticateManager implements AuthenticationService{

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtManager jwtManager;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional(readOnly = false)
    public GetAuthenticationResponse register(CreateRegisterRequest createRegisterRequest) {
        User user = User.builder()
        .firstName(createRegisterRequest.getFirstName())
        .email(createRegisterRequest.getEmail())
        .lastName(createRegisterRequest.getLastName())
        .password(this.passwordEncoder.encode(createRegisterRequest.getPassword()))
        .role(Role.USER)
        .build();

        // add user to userRepository
        this.userRepository.save(user);

        // create new token for the user
        String jwtToken = this.jwtManager.generateToken(user);

        // return token in response
        return GetAuthenticationResponse.builder()
            .token(jwtToken).build();
    }

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "AuthenticationService::findByEmail", key = "#createAuthenticationRequest.email")
    public GetAuthenticationResponse authenticate(CreateAuthenticationRequest createAuthenticationRequest) {
        this.authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                createAuthenticationRequest.getEmail(), createAuthenticationRequest.getPassword())
        );
        User user = this.userRepository.findByEmail(createAuthenticationRequest.getEmail()).orElseThrow();
        String jwtToken = this.jwtManager.generateToken(user);
        return GetAuthenticationResponse.builder()
            .token(jwtToken).build();
    }
}
