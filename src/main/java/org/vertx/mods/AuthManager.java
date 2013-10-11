/*
 * Copyright 2011-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.vertx.mods;

import org.vertx.java.busmods.BusModBase;
import org.vertx.java.core.Handler;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.json.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;


/**
 * Basic Authentication Manager Bus Module<p>
 * Please see the busmods manual for a full description<p>
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthManager extends BusModBase {

  private Handler<Message<JsonObject>> loginHandler;
  private Handler<Message<JsonObject>> logoutHandler;
  private Handler<Message<JsonObject>> authoriseHandler;

  protected final Map<String, UserSessionManager> sessions = new HashMap<>();

  private static final long DEFAULT_SESSION_TIMEOUT = 30 * 60 * 1000;
  private static final int DEFAULT_MAX_CONCURRENT_CONNECTIONS = 1;

  private String address;
  private String userCollection;
  private String persistorAddress;
  private long sessionTimeout;
  private int maxConcurrentConnections;

  private static final class LoginInfo {
    final long timerID;

    private LoginInfo(long timerID) {
      this.timerID = timerID;
    }
  }

  private static final class UserSessionManager {
    private final String username;
    private final List<String> sessions = new ArrayList<>();
    private final Map<String, LoginInfo> logins = new HashMap<>();

    public UserSessionManager(String username) {
      this.username = username;
    }

    public String getUsername() {
      return this.username;
    }

    public LoginInfo getLoginInfo(String sessionID) {
      if (!sessions.contains(sessionID)) {
        return null;
      }
      return logins.get(sessionID);
    }

    public void add(String sessionID, LoginInfo loginInfo) {
      if (this.logins.containsKey(sessionID)) {
        return;
      }
      this.logins.put(sessionID, loginInfo);
      this.sessions.add(sessionID);
    }

    public void remove(String sessionID) {
      if (this.logins.containsKey(sessionID)) {
        this.logins.remove(sessionID);
        this.sessions.remove(sessionID);
      }
    }

    public int size() {
      return this.logins.size();
    }

    public String getOldestSessionID() {
      if (this.sessions.isEmpty()) {
        return null;
      } else {
        return sessions.get(0);
      }
    }
  }

  /**
   * Start the busmod
   */
  public void start() {
    super.start();

    this.address = getOptionalStringConfig("address", "vertx.basicauthmanager");
    this.userCollection = getOptionalStringConfig("user_collection", "users");
    this.persistorAddress = getOptionalStringConfig("persistor_address", "vertx.mongopersistor");
    Number timeout = config.getNumber("session_timeout");
    if (timeout != null) {
      if (timeout instanceof Long) {
        this.sessionTimeout = (Long)timeout;
      } else if (timeout instanceof Integer) {
        this.sessionTimeout = (Integer)timeout;
      }
    } else {
      this.sessionTimeout = DEFAULT_SESSION_TIMEOUT;
    }
    Number maxConnectionsPerUser = config.getNumber("max_connections_per_user", DEFAULT_MAX_CONCURRENT_CONNECTIONS);
    if (maxConnectionsPerUser instanceof Integer) {
      this.maxConcurrentConnections = (Integer)maxConnectionsPerUser;
    } else {
      this.maxConcurrentConnections = DEFAULT_MAX_CONCURRENT_CONNECTIONS;
    }
    // set actual unlimited number if maxConcurrentConnections was -1
    if (this.maxConcurrentConnections == -1) {
      this.maxConcurrentConnections = Integer.MAX_VALUE;
    } else if (this.maxConcurrentConnections <= 0) {
      this.maxConcurrentConnections = DEFAULT_MAX_CONCURRENT_CONNECTIONS;
    }

    loginHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doLogin(message);
      }
    };
    eb.registerHandler(address + ".login", loginHandler);
    logoutHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doLogout(message);
      }
    };
    eb.registerHandler(address + ".logout", logoutHandler);
    authoriseHandler = new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> message) {
        doAuthorise(message);
      }
    };
    eb.registerHandler(address + ".authorise", authoriseHandler);
  }

  private void doLogin(final Message<JsonObject> message) {

    final String username = getMandatoryString("username", message);
    if (username == null) {
      return;
    }
    String password = getMandatoryString("password", message);
    if (password == null) {
      return;
    }

    JsonObject findMsg = new JsonObject().putString("action", "findone").putString("collection", userCollection);
    JsonObject matcher = new JsonObject().putString("username", username).putString("password", password);
    findMsg.putObject("matcher", matcher);

    eb.send(persistorAddress, findMsg, new Handler<Message<JsonObject>>() {
      public void handle(Message<JsonObject> reply) {

        if (reply.body().getString("status").equals("ok")) {
          if (reply.body().getObject("result") != null) {

            UserSessionManager sm = sessions.get(username);
            logger.debug("UserSessionManager: " + sm);
            if (sm == null) {
              sessions.put(username, new UserSessionManager(username));
              sm = sessions.get(username);
              logger.debug("UserSessionManager was generated: " + sm);
            }

            // Found
            final String sessionID = UUID.randomUUID().toString();
            long timerID = vertx.setTimer(sessionTimeout, new Handler<Long>() {
              public void handle(Long timerID) {
                UserSessionManager sm = getUserSessionManager(sessionID);
                if (sm != null) {
                  sm.remove(sessionID);
                  if (sm.size() == 0) {
                    sessions.remove(username);
                  }
                }
              }
            });
            sm.add(sessionID, new LoginInfo(timerID));

            // Check if already the number of logged in exceeds the number of max concurrent connections
            logger.debug("The number of connections[" + username + "]: " + sm.size());
            if (sm.size() > maxConcurrentConnections) {
              String oldestSessionID = sm.getOldestSessionID();
              logout(oldestSessionID);
              logger.debug("Oldest connection was purged[" + username + "]: " + sm.size());
            }

            JsonObject jsonReply = new JsonObject().putString("sessionID", sessionID);
            sendOK(message, jsonReply);
          } else {
            // Not found
            sendStatus("denied", message);
          }
        } else {
          logger.error("Failed to execute login query: " + reply.body().getString("message"));
          sendError(message, "Failed to excecute login");
        }
      }
    });
  }

  protected void doLogout(final Message<JsonObject> message) {
    final String sessionID = getMandatoryString("sessionID", message);
    if (sessionID != null) {
      if (logout(sessionID)) {
        sendOK(message);
      } else {
        super.sendError(message, "Not logged in");
      }
    }
  }

  protected boolean logout(String sessionID) {
    UserSessionManager sm = getUserSessionManager(sessionID);
    if (sm == null) {
      return false;
    }
    LoginInfo loginInfo = sm.getLoginInfo(sessionID);
    if (loginInfo != null) {
      sm.remove(sessionID);
      if (sm.size() == 0) {
        this.sessions.remove(sm.getUsername());
      }
      vertx.cancelTimer(loginInfo.timerID);
      return true;
    } else {
      return false;
    }
  }

  protected void doAuthorise(Message<JsonObject> message) {
    String sessionID = getMandatoryString("sessionID", message);
    if (sessionID == null) {
      return;
    }
    UserSessionManager sm = getUserSessionManager(sessionID);

    // In this basic auth manager we don't do any resource specific authorisation
    // The user is always authorised if they are logged in

    if (sm != null) {
      logger.debug("The number of connections[" + sm.getUsername() + "]: " + sm.size());
      JsonObject reply = new JsonObject().putString("username", sm.getUsername());
      sendOK(message, reply);
    } else {
      sendStatus("denied", message);
    }
  }

  protected UserSessionManager getUserSessionManager(String sessionID) {
    for (Map.Entry<String, UserSessionManager> entry : this.sessions.entrySet()) {
      LoginInfo loginInfo = entry.getValue().getLoginInfo(sessionID);
      if (loginInfo != null) {
        return entry.getValue();
      }
    }
    return null;
  }
}
