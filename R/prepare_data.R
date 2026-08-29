# prepare_data.R
# Hossein Tabasi
#
# NSL-KDD loaders and the training-time feature recipe.
#
# What this file does (no model fitting here):
#   1. Read official KDDTrain+.txt / KDDTest+.txt (41 features + label + difficulty).
#   2. Attach a binary target: normal vs attack (anything other than "normal").
#   3. Attach an attack-family label for EDA only (DoS / Probe / R2L / U2R / normal).
#   4. Restrict to a documented 21-feature subset.
#   5. Downsample the majority class on TRAIN only, then cap each class.
#   6. Learn factor levels, dummy column names, and numeric scaler from TRAIN only.
#   7. Transform train and test with that frozen recipe (no test leakage).
#
# Run as a library from train_models.R, or standalone:
#   Rscript R/prepare_data.R
# Standalone writes models/feature_recipe.rds and a short data/prepare_summary.txt.

NSL_COLUMNS <- c(
  "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
  "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
  "num_compromised", "root_shell", "su_attempted", "num_root",
  "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
  "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
  "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
  "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
  "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
  "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
  "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
  "dst_host_srv_rerror_rate", "label", "difficulty"
)

# Standard NSL-KDD family lists (Tavallaee et al. 2009 plus the extra
# KDDTest+ labels that do not appear in KDDTrain+). Used for EDA only.
DOS_LABELS <- c(
  "apache2", "back", "land", "mailbomb", "neptune", "pod",
  "processtable", "smurf", "teardrop", "udpstorm", "worm"
)
PROBE_LABELS <- c("ipsweep", "mscan", "nmap", "portsweep", "saint", "satan")
R2L_LABELS <- c(
  "ftp_write", "guess_passwd", "httptunnel", "imap", "multihop", "named",
  "phf", "sendmail", "snmpgetattack", "snmpguess", "spy",
  "warezclient", "warezmaster", "xlock", "xsnoop"
)
U2R_LABELS <- c(
  "buffer_overflow", "loadmodule", "perl", "ps", "rootkit", "sqlattack", "xterm"
)

# 23-feature subset. Justification is in README.md: common IDS traffic /
# host-based rates from the NSL-KDD literature, with highly redundant
# siblings (srv_serror_rate, dst_host_srv_serror_rate, ...) dropped.
# protocol_type and flag are kept in full. service has 70+ levels, so it is
# collapsed to the top 12 training values plus "rare" before dummy encoding.
CAT_FEATURES <- c("protocol_type", "flag", "service")
NUM_FEATURES <- c(
  "duration", "src_bytes", "dst_bytes", "wrong_fragment", "hot", "logged_in",
  "count", "srv_count", "serror_rate", "rerror_rate", "same_srv_rate",
  "diff_srv_rate", "dst_host_count", "dst_host_srv_count",
  "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
  "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
  "dst_host_serror_rate", "dst_host_rerror_rate"
)
LOG_FEATURES <- c("duration", "src_bytes", "dst_bytes")
SELECTED_FEATURES <- c(CAT_FEATURES, NUM_FEATURES)
TOP_N_SERVICES <- 12L
CLASS_LEVELS <- c("normal", "attack")

# Default cap after balancing: 12,000 rows per class (~24k train rows).
# randomForest ntree=100 on this size finishes in a few minutes on a laptop.
CAP_PER_CLASS_DEFAULT <- 12000L
DOWNSAMPLE_SEED <- 42L

TRAIN_URL <- "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt"
TEST_URL  <- "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

nsl_project_root <- function() {
  args <- commandArgs(trailingOnly = FALSE)
  file_arg <- grep("^--file=", args, value = TRUE)
  if (length(file_arg) == 1) {
    this_file <- normalizePath(sub("^--file=", "", file_arg))
    return(normalizePath(file.path(dirname(this_file), "..")))
  }
  # Sourced from another script: walk up from getwd() until data/ is visible.
  cand <- normalizePath(getwd())
  if (file.exists(file.path(cand, "data")) && file.exists(file.path(cand, "R"))) {
    return(cand)
  }
  if (file.exists(file.path(cand, "..", "data"))) {
    return(normalizePath(file.path(cand, "..")))
  }
  cand
}

# -----------------------------------------------------------------------------
# Labels
# -----------------------------------------------------------------------------

map_attack_family <- function(label) {
  lab <- tolower(trimws(as.character(label)))
  fam <- rep("other_attack", length(lab))
  fam[lab == "normal"] <- "normal"
  fam[lab %in% DOS_LABELS] <- "DoS"
  fam[lab %in% PROBE_LABELS] <- "Probe"
  fam[lab %in% R2L_LABELS] <- "R2L"
  fam[lab %in% U2R_LABELS] <- "U2R"
  fam
}

make_binary_label <- function(label) {
  lab <- tolower(trimws(as.character(label)))
  factor(ifelse(lab == "normal", "normal", "attack"), levels = CLASS_LEVELS)
}

# -----------------------------------------------------------------------------
# Download / load
# -----------------------------------------------------------------------------

download_nsl_kdd <- function(data_dir) {
  dir.create(data_dir, showWarnings = FALSE, recursive = TRUE)
  train_path <- file.path(data_dir, "KDDTrain+.txt")
  test_path  <- file.path(data_dir, "KDDTest+.txt")
  if (!file.exists(train_path)) {
    message("Downloading KDDTrain+.txt ...")
    utils::download.file(TRAIN_URL, train_path, mode = "wb", quiet = FALSE)
  }
  if (!file.exists(test_path)) {
    message("Downloading KDDTest+.txt ...")
    utils::download.file(TEST_URL, test_path, mode = "wb", quiet = FALSE)
  }
  invisible(list(train = train_path, test = test_path))
}

read_nsl_file <- function(path) {
  if (!file.exists(path)) {
    stop("NSL-KDD file not found: ", path, ". See data/README.md.")
  }
  raw <- utils::read.csv(
    path,
    header           = FALSE,
    stringsAsFactors = FALSE,
    col.names        = NSL_COLUMNS
  )
  if (ncol(raw) != length(NSL_COLUMNS)) {
    stop("Expected ", length(NSL_COLUMNS), " columns in ", path,
         " but got ", ncol(raw), ".")
  }
  # Force numeric columns to numeric (read.csv may pick integer).
  for (nm in setdiff(NSL_COLUMNS, c("protocol_type", "service", "flag", "label"))) {
    raw[[nm]] <- as.numeric(raw[[nm]])
  }
  raw$label         <- tolower(trimws(as.character(raw$label)))
  raw$binary_label  <- make_binary_label(raw$label)
  raw$attack_family <- map_attack_family(raw$label)
  raw
}

load_nsl_kdd <- function(root = nsl_project_root()) {
  data_dir <- file.path(root, "data")
  download_nsl_kdd(data_dir)
  train <- read_nsl_file(file.path(data_dir, "KDDTrain+.txt"))
  test  <- read_nsl_file(file.path(data_dir, "KDDTest+.txt"))
  message(sprintf(
    "Loaded official NSL-KDD: train %d rows (%d normal, %d attack); test %d rows (%d normal, %d attack).",
    nrow(train),
    sum(train$binary_label == "normal"),
    sum(train$binary_label == "attack"),
    nrow(test),
    sum(test$binary_label == "normal"),
    sum(test$binary_label == "attack")
  ))
  list(train = train, test = test)
}

# -----------------------------------------------------------------------------
# Downsample TRAIN only
# -----------------------------------------------------------------------------

#' Balance binary classes on TRAIN, then cap each class.
#'
#' Majority class is downsampled to the minority size (without replacement).
#' If that balanced table is still larger than 2 * cap_per_class, each class
#' is capped at cap_per_class. The official test table is never touched.
downsample_train <- function(train, cap_per_class = CAP_PER_CLASS_DEFAULT,
                             seed = DOWNSAMPLE_SEED) {
  set.seed(as.integer(seed))
  y <- train$binary_label
  idx_n <- which(y == "normal")
  idx_a <- which(y == "attack")
  n_n <- length(idx_n)
  n_a <- length(idx_a)
  # Step 1: downsample majority to minority size.
  n_bal <- min(n_n, n_a)
  if (n_n > n_bal) idx_n <- sample(idx_n, n_bal)
  if (n_a > n_bal) idx_a <- sample(idx_a, n_bal)
  # Step 2: cap each class for the laptop budget.
  cap <- as.integer(cap_per_class)
  if (length(idx_n) > cap) idx_n <- sample(idx_n, cap)
  if (length(idx_a) > cap) idx_a <- sample(idx_a, cap)
  keep <- sample(c(idx_n, idx_a))  # shuffle so classes are not blocked
  out <- train[keep, , drop = FALSE]
  rownames(out) <- NULL
  message(sprintf(
    "Downsampled TRAIN (seed=%s): full normal=%d attack=%d -> balanced+capped normal=%d attack=%d (n=%d).",
    seed, n_n, n_a,
    sum(out$binary_label == "normal"),
    sum(out$binary_label == "attack"),
    nrow(out)
  ))
  attr(out, "downsample") <- list(
    seed            = as.integer(seed),
    cap_per_class   = cap,
    full_normal     = n_n,
    full_attack     = n_a,
    used_normal     = sum(out$binary_label == "normal"),
    used_attack     = sum(out$binary_label == "attack"),
    used_n          = nrow(out)
  )
  out
}

# -----------------------------------------------------------------------------
# Recipe: factor levels, dummies, scaler (TRAIN only)
# -----------------------------------------------------------------------------

mode_value <- function(x) {
  x <- as.character(x)
  x <- x[!is.na(x) & nzchar(x)]
  if (length(x) == 0) return(NA_character_)
  names(sort(table(x), decreasing = TRUE))[1]
}

top_services <- function(x, n = TOP_N_SERVICES) {
  x <- as.character(x)
  x <- x[!is.na(x) & nzchar(x)]
  names(sort(table(x), decreasing = TRUE))[seq_len(min(n, length(unique(x))))]
}

collapse_service <- function(x, top) {
  x <- as.character(x)
  x[is.na(x) | !(x %in% top)] <- "rare"
  x
}

dummy_encode <- function(df, cat_features, factor_levels) {
  n <- nrow(df)
  parts <- list()
  for (nm in cat_features) {
    lv <- factor_levels[[nm]]
    x  <- as.character(df[[nm]])
    x[is.na(x) | !(x %in% lv)] <- lv[[1]]  # unseen -> first training level
    mat <- matrix(0, nrow = n, ncol = length(lv))
    colnames(mat) <- paste0(nm, "_", lv)
    for (j in seq_along(lv)) {
      mat[, j] <- as.numeric(x == lv[[j]])
    }
    parts[[nm]] <- mat
  }
  do.call(cbind, parts)
}

#' Learn a frozen featuriser from the (already downsampled) training table.
build_recipe <- function(train) {
  missing_cols <- setdiff(SELECTED_FEATURES, names(train))
  if (length(missing_cols) > 0) {
    stop("Training table is missing selected features: ",
         paste(missing_cols, collapse = ", "))
  }

  work <- train
  top_svc <- top_services(work$service, TOP_N_SERVICES)
  work$service <- collapse_service(work$service, top_svc)

  factor_levels <- lapply(CAT_FEATURES, function(nm) {
    sort(unique(as.character(work[[nm]])))
  })
  names(factor_levels) <- CAT_FEATURES
  # Keep "rare" even if every training service was inside the top-N.
  if (!"rare" %in% factor_levels$service) {
    factor_levels$service <- sort(c(factor_levels$service, "rare"))
  }

  # Log1p then scale numeric columns. Dummy columns stay 0/1.
  num_mat <- as.matrix(work[, NUM_FEATURES, drop = FALSE])
  storage.mode(num_mat) <- "double"
  for (nm in LOG_FEATURES) {
    num_mat[, nm] <- log1p(pmax(num_mat[, nm], 0))
  }
  center <- colMeans(num_mat, na.rm = TRUE)
  scale  <- apply(num_mat, 2, stats::sd, na.rm = TRUE)
  scale[!is.finite(scale) | scale == 0] <- 1

  dummy_train <- dummy_encode(work, CAT_FEATURES, factor_levels)
  dummy_names <- colnames(dummy_train)
  feature_names <- c(dummy_names, NUM_FEATURES)

  # Defaults for Shiny fields that the user does not fill in.
  defaults <- list()
  for (nm in CAT_FEATURES) {
    defaults[[nm]] <- mode_value(work[[nm]])
  }
  for (nm in NUM_FEATURES) {
    defaults[[nm]] <- stats::median(as.numeric(work[[nm]]), na.rm = TRUE)
  }

  list(
    selected_features = SELECTED_FEATURES,
    cat_features      = CAT_FEATURES,
    num_features      = NUM_FEATURES,
    log_features      = LOG_FEATURES,
    top_services      = top_svc,
    factor_levels     = factor_levels,
    dummy_names       = dummy_names,
    feature_names     = feature_names,
    scaler_center     = center,
    scaler_scale      = scale,
    defaults          = defaults,
    class_levels      = CLASS_LEVELS,
    cap_per_class     = CAP_PER_CLASS_DEFAULT,
    downsample_seed   = DOWNSAMPLE_SEED
  )
}

#' Apply a frozen recipe to a data.frame of raw NSL-KDD columns.
#'
#' Missing selected columns are filled from training defaults so a short
#' Shiny form (8–12 fields) still produces a full model row.
apply_recipe <- function(df, recipe) {
  n <- nrow(df)
  if (n == 0) {
    stop("apply_recipe() received zero rows.")
  }
  work <- as.data.frame(df, stringsAsFactors = FALSE)

  for (nm in recipe$selected_features) {
    if (!nm %in% names(work)) {
      work[[nm]] <- recipe$defaults[[nm]]
    }
  }

  if ("service" %in% recipe$cat_features && !is.null(recipe$top_services)) {
    work$service <- collapse_service(work$service, recipe$top_services)
  }

  for (nm in recipe$cat_features) {
    work[[nm]] <- as.character(work[[nm]])
    lv <- recipe$factor_levels[[nm]]
    bad <- is.na(work[[nm]]) | !(work[[nm]] %in% lv)
    if (any(bad)) {
      work[[nm]][bad] <- lv[[1]]
    }
  }

  for (nm in recipe$num_features) {
    work[[nm]] <- as.numeric(work[[nm]])
    if (anyNA(work[[nm]])) {
      work[[nm]][is.na(work[[nm]])] <- recipe$defaults[[nm]]
    }
  }

  dummies <- dummy_encode(work, recipe$cat_features, recipe$factor_levels)
  # Guard: column order of dummy_encode follows factor_levels, which is frozen.
  dummies <- dummies[, recipe$dummy_names, drop = FALSE]

  num_mat <- as.matrix(work[, recipe$num_features, drop = FALSE])
  storage.mode(num_mat) <- "double"
  for (nm in recipe$log_features) {
    num_mat[, nm] <- log1p(pmax(num_mat[, nm], 0))
  }
  num_mat <- sweep(num_mat, 2, recipe$scaler_center, "-")
  num_mat <- sweep(num_mat, 2, recipe$scaler_scale,  "/")

  x <- data.frame(dummies, num_mat, check.names = FALSE)
  x <- x[, recipe$feature_names, drop = FALSE]

  y <- NULL
  if ("binary_label" %in% names(work)) {
    y <- factor(as.character(work$binary_label), levels = recipe$class_levels)
  } else if ("label" %in% names(work)) {
    y <- make_binary_label(work$label)
  }

  list(x = x, y = y)
}

# -----------------------------------------------------------------------------
# Full pipeline used by train_models.R
# -----------------------------------------------------------------------------

prepare_nsl_pipeline <- function(root = nsl_project_root(),
                                 cap_per_class = CAP_PER_CLASS_DEFAULT,
                                 seed = DOWNSAMPLE_SEED) {
  raw <- load_nsl_kdd(root)
  train_fit <- downsample_train(raw$train, cap_per_class = cap_per_class, seed = seed)
  recipe <- build_recipe(train_fit)
  recipe$downsample <- attr(train_fit, "downsample")
  recipe$n_train_full <- nrow(raw$train)
  recipe$n_test_full  <- nrow(raw$test)
  recipe$n_train_full_normal <- sum(raw$train$binary_label == "normal")
  recipe$n_train_full_attack <- sum(raw$train$binary_label == "attack")
  recipe$n_test_full_normal  <- sum(raw$test$binary_label == "normal")
  recipe$n_test_full_attack  <- sum(raw$test$binary_label == "attack")

  tr <- apply_recipe(train_fit, recipe)
  te <- apply_recipe(raw$test, recipe)
  message(sprintf(
    "Model matrix: %d train rows x %d columns; test %d rows (official KDDTest+, not reshuffled).",
    nrow(tr$x), ncol(tr$x), nrow(te$x)
  ))
  list(
    train_full = raw$train,
    test_full  = raw$test,
    train_fit  = train_fit,
    recipe     = recipe,
    train_x    = tr$x,
    train_y    = tr$y,
    test_x     = te$x,
    test_y     = te$y
  )
}

# -----------------------------------------------------------------------------
# Standalone
# -----------------------------------------------------------------------------

if (sys.nframe() == 0L) {
  root <- nsl_project_root()
  setwd(root)
  message("Project root: ", root)
  prep <- prepare_nsl_pipeline(root)
  dir.create(file.path(root, "models"), showWarnings = FALSE, recursive = TRUE)
  saveRDS(prep$recipe, file.path(root, "models", "feature_recipe.rds"))
  saveRDS(prep$recipe$feature_names, file.path(root, "models", "feature_names.rds"))
  saveRDS(
    list(center = prep$recipe$scaler_center, scale = prep$recipe$scaler_scale),
    file.path(root, "models", "scaler.rds")
  )
  saveRDS(prep$recipe$factor_levels, file.path(root, "models", "factor_levels.rds"))
  summary_path <- file.path(root, "data", "prepare_summary.txt")
  ds <- prep$recipe$downsample
  writeLines(c(
    "NSL-KDD prepare_data.R summary (Hossein Tabasi)",
    sprintf("Official train rows: %d (normal=%d, attack=%d)",
            prep$recipe$n_train_full,
            prep$recipe$n_train_full_normal,
            prep$recipe$n_train_full_attack),
    sprintf("Official test rows:  %d (normal=%d, attack=%d)",
            prep$recipe$n_test_full,
            prep$recipe$n_test_full_normal,
            prep$recipe$n_test_full_attack),
    sprintf("Fit set after downsample (seed=%s, cap=%s): n=%d (normal=%d, attack=%d)",
            ds$seed, ds$cap_per_class, ds$used_n, ds$used_normal, ds$used_attack),
    sprintf("Feature columns: %d", length(prep$recipe$feature_names)),
    paste("Selected raw features:", paste(SELECTED_FEATURES, collapse = ", "))
  ), summary_path)
  message("Wrote ", summary_path)
  message("Recipe RDS written under models/. Fit models with: Rscript R/train_models.R")
}
