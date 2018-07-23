package com.epam.reportportal.auth.integration.github;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.epam.ta.reportportal.dao.UserRepository;

public class GitHubOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
  private static final Logger LOGGER = LoggerFactory.getLogger(GitHubOAuth2UserService.class);
  private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";
  private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";
  private UserRepository userRepository;
  private GitHubUserReplicator userReplicator;


  public GitHubOAuth2UserService(UserRepository userRepository, GitHubUserReplicator userReplicator) {
    this.userRepository = userRepository;
    this.userReplicator = userReplicator;
  }

  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    Assert.notNull(userRequest, "userRequest cannot be null");
    if (!"github".equalsIgnoreCase(userRequest.getClientRegistration().getRegistrationId())) {
      return null;
    }
    if (!StringUtils.hasText(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())) {
      OAuth2Error oauth2Error = new OAuth2Error(
          MISSING_USER_INFO_URI_ERROR_CODE,
          "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: " +
              userRequest.getClientRegistration().getRegistrationId(),
          null
      );
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
    if (!StringUtils.hasText(userNameAttributeName)) {
      OAuth2Error oauth2Error = new OAuth2Error(
          MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
          "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: " +
              userRequest.getClientRegistration().getRegistrationId(),
          null
      );
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    //TODO: some checks for orgs
    GitHubClient gitHubClient = GitHubClient.withAccessToken(userRequest.getAccessToken().getTokenValue());
    Map<String, Object> userAttributes = gitHubClient.getUserAttributes();
    GrantedAuthority authority = new OAuth2UserAuthority(userAttributes);
    Set<GrantedAuthority> authorities = new HashSet<>();
    authorities.add(authority);
    userReplicator.replicateUser(userRequest.getAccessToken().getTokenValue());
    return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
  }
}
