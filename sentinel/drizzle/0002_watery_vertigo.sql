CREATE TABLE `threat_feed_cache` (
	`source` text PRIMARY KEY NOT NULL,
	`payload` text,
	`fetched_at` integer,
	`last_attempt_at` integer NOT NULL,
	`next_attempt_at` integer NOT NULL,
	`fetching_until` integer NOT NULL,
	`last_error` text,
	`etag` text,
	`last_modified` text
);
