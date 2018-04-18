drop keyspace if exists userdata;
create keyspace userdata
  WITH replication = {
    'class' : 'SimpleStrategy',
    'replication_factor' : 1
};

USE userdata;

drop table if exists userdata.user;
create table user (
  username text,
  user_id uuid,
  email text,
  pw_hash text,
  PRIMARY KEY (username, user_id)
);

drop table if exists userdata.message;
create table message (
  author_id uuid,
  username text,
  pub_date int,
  email text,
  text text,
  following set<uuid>,
  PRIMARY KEY((author_id, username), pub_date)
);

CREATE INDEX following_idx ON userdata.message(following);
