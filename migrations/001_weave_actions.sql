create table if not exists weave_actions (
  recipe_id text not null,
  action text not null,
  window_id text not null,
  status text not null,
  deadline timestamptz not null,
  primary key (recipe_id, action, window_id)
);
