
DROP TABLE IF EXISTS `oauth2`.`oauth_client_details`;
CREATE TABLE `oauth2`.`oauth_client_details` (
  `client_id` varchar(255) NOT NULL,
  `resource_ids` varchar(255) DEFAULT NULL,
  `client_secret` varchar(255) DEFAULT NULL,
  `scope` varchar(255) DEFAULT NULL,
  `authorized_grant_types` varchar(255) DEFAULT NULL,
  `web_server_redirect_uri` varchar(255) DEFAULT NULL,
  `authorities` varchar(255) DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additional_information` varchar(255) DEFAULT NULL,
  `autoapprove` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `oauth2`.`oauth_client_details` VALUES ('myclient', null, '$2a$10$tEFtDKpFh6eAr07inuDYVOtVAArj1NK3ulnj8KuUp7rHjrjYPzzD.', 'resource-server-read,resource-server-write', 'client_credentials', null, 'ROLE_USER', '300', null, null, null);
INSERT INTO `oauth2`.`oauth_client_details` VALUES ('ResourceServer', null, '$2a$10$0rrAX0SkBmnQhkLjPmgJkuivkU.D5iUisgyeMFk8k0MQCLwHXw5kC', null, 'authorization_code,implicit,password,client_credentials,refresh_token', null, 'ROLE_TRUSTED_CLIENT', null, null, null, null);
