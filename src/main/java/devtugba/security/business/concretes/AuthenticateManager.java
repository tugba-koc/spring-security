package devtugba.security.business.concretes;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import devtugba.security.business.abstracts.AuthenticationService;
import devtugba.security.business.requests.CreateAuthenticationRequest;
import devtugba.security.business.requests.CreateRegisterRequest;
import devtugba.security.business.responses.GetAuthenticationResponse;
import devtugba.security.config.concretes.JwtManager;
import devtugba.security.constants.Role;
import devtugba.security.dataAccess.abstracts.UserRepository;
import devtugba.security.entities.concretes.User;

@Service
public class AuthenticateManager implements AuthenticationService{

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtManager jwtManager;
    private AuthenticationManager authenticationManager;


    public AuthenticateManager(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtManager jwtManager, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtManager = jwtManager;
        this.authenticationManager = authenticationManager;
    }

    @Override
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
