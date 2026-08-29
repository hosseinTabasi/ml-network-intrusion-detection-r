# train_models.R
# Hossein Tabasi
#
# Fit a decision tree (rpart) and a Random Forest (ntree = 100) on a
# downsampled official KDDTrain+ table. Evaluate on official KDDTest+ only.
# The model with the highest attack-class recall (then attack F1, then
# accuracy) is written to models/best_model.rds.
#
# From the project root:
#   Rscript R/train_models.R

options(stringsAsFactors = FALSE)
set.seed(42)

args <- commandArgs(trailingOnly = FALSE)
file_arg <- grep("^--file=", args, value = TRUE)
if (length(file_arg) == 1) {
  this_file <- normalizePath(sub("^--file=", "", file_arg))
  root <- normalizePath(file.path(dirname(this_file), ".."))
} else {
  root <- getwd()
}
setwd(root)
message("Project root: ", root)

dir.create(file.path(root, "models"),  showWarnings = FALSE, recursive = TRUE)
dir.create(file.path(root, "figures"), showWarnings = FALSE, recursive = TRUE)

suppressPackageStartupMessages({
  library(ggplot2)
  library(tidyr)
  library(caret)
  library(rpart)
  library(randomForest)
  library(jsonlite)
})

source(file.path(root, "R", "prepare_data.R"))
source(file.path(root, "R", "eda.R"))

# -----------------------------------------------------------------------------
# Data
# -----------------------------------------------------------------------------
prep <- prepare_nsl_pipeline(root, cap_per_class = CAP_PER_CLASS_DEFAULT,
                             seed = DOWNSAMPLE_SEED)

run_eda(prep$train_full, file.path(root, "figures"))

train_x <- prep$train_x
train_y <- prep$train_y
test_x  <- prep$test_x
test_y  <- prep$test_y
recipe  <- prep$recipe

# -----------------------------------------------------------------------------
# Metrics on TEST only
# -----------------------------------------------------------------------------
binary_metrics <- function(truth, pred, model_name) {
  truth <- factor(as.character(truth), levels = CLASS_LEVELS)
  pred  <- factor(as.character(pred),  levels = CLASS_LEVELS)
  tab <- table(truth, pred, dnn = c("True", "Predicted"))
  # Ensure 2 x 2 even if a class is missing in predictions.
  tab <- tab[CLASS_LEVELS, CLASS_LEVELS, drop = FALSE]
  tab[is.na(tab)] <- 0

  tn <- as.numeric(tab["normal", "normal"])
  fp <- as.numeric(tab["normal", "attack"])
  fn <- as.numeric(tab["attack", "normal"])
  tp <- as.numeric(tab["attack", "attack"])
  n  <- tn + fp + fn + tp

  acc <- (tp + tn) / n
  prec_a <- if ((tp + fp) == 0) 0 else tp / (tp + fp)
  rec_a  <- if ((tp + fn) == 0) 0 else tp / (tp + fn)
  f1_a   <- if ((prec_a + rec_a) == 0) 0 else 2 * prec_a * rec_a / (prec_a + rec_a)
  prec_n <- if ((tn + fn) == 0) 0 else tn / (tn + fn)
  rec_n  <- if ((tn + fp) == 0) 0 else tn / (tn + fp)
  f1_n   <- if ((prec_n + rec_n) == 0) 0 else 2 * prec_n * rec_n / (prec_n + rec_n)

  list(
    model              = model_name,
    n_test             = as.integer(n),
    accuracy           = acc,
    attack_precision   = prec_a,
    attack_recall      = rec_a,
    attack_f1          = f1_a,
    normal_precision   = prec_n,
    normal_recall      = rec_n,
    normal_f1          = f1_n,
    tn = as.integer(tn), fp = as.integer(fp),
    fn = as.integer(fn), tp = as.integer(tp),
    confusion = as.list(as.data.frame.matrix(tab))
  )
}

fmt4 <- function(x) sprintf("%.4f", x)

# -----------------------------------------------------------------------------
# Model 1: rpart decision tree
# -----------------------------------------------------------------------------
message("Fitting rpart decision tree ...")
t_rpart <- system.time({
  train_df <- train_x
  train_df$y <- train_y
  model_rpart <- rpart(
    y ~ .,
    data    = train_df,
    method  = "class",
    control = rpart.control(cp = 0.001, minsplit = 40, maxdepth = 16)
  )
})
message(sprintf("rpart fit time: %.1f s", t_rpart[["elapsed"]]))

pred_rpart <- predict(model_rpart, newdata = test_x, type = "class")
pred_rpart <- factor(as.character(pred_rpart), levels = CLASS_LEVELS)
met_rpart  <- binary_metrics(test_y, pred_rpart, "rpart")
met_rpart$fit_seconds <- unname(t_rpart[["elapsed"]])

# -----------------------------------------------------------------------------
# Model 2: randomForest, ntree = 100
# -----------------------------------------------------------------------------
message("Fitting randomForest (ntree = 100) ...")
p_feat <- ncol(train_x)
t_rf <- system.time({
  model_rf <- randomForest(
    x          = train_x,
    y          = train_y,
    ntree      = 100,
    mtry       = max(1L, floor(sqrt(p_feat))),
    importance = TRUE,
    nodesize   = 5
  )
})
message(sprintf("randomForest fit time: %.1f s", t_rf[["elapsed"]]))

pred_rf <- predict(model_rf, newdata = test_x, type = "response")
pred_rf <- factor(as.character(pred_rf), levels = CLASS_LEVELS)
met_rf  <- binary_metrics(test_y, pred_rf, "randomForest")
met_rf$fit_seconds <- unname(t_rf[["elapsed"]])
met_rf$ntree <- 100L
met_rf$mtry  <- max(1L, floor(sqrt(p_feat)))

# -----------------------------------------------------------------------------
# Choose BEST by attack recall, then attack F1, then accuracy
# -----------------------------------------------------------------------------
score_key <- function(m) {
  c(m$attack_recall, m$attack_f1, m$accuracy)
}
s_rpart <- score_key(met_rpart)
s_rf    <- score_key(met_rf)
rf_wins <- (s_rf[1] > s_rpart[1]) ||
  (s_rf[1] == s_rpart[1] && s_rf[2] > s_rpart[2]) ||
  (s_rf[1] == s_rpart[1] && s_rf[2] == s_rpart[2] && s_rf[3] >= s_rpart[3])

if (rf_wins) {
  best_model <- model_rf
  best_met   <- met_rf
  best_name  <- "randomForest"
  best_pred  <- pred_rf
} else {
  best_model <- model_rpart
  best_met   <- met_rpart
  best_name  <- "rpart"
  best_pred  <- pred_rpart
}

message(sprintf(
  "BEST model: %s | test accuracy=%s | attack recall=%s | attack F1=%s",
  best_name, fmt4(best_met$accuracy), fmt4(best_met$attack_recall),
  fmt4(best_met$attack_f1)
))

# -----------------------------------------------------------------------------
# Persist everything the Shiny app / predict_connection() need
# -----------------------------------------------------------------------------
saveRDS(best_model,              file.path(root, "models", "best_model.rds"))
saveRDS(model_rpart,             file.path(root, "models", "rpart_model.rds"))
saveRDS(model_rf,                file.path(root, "models", "rf_model.rds"))
saveRDS(recipe,                  file.path(root, "models", "feature_recipe.rds"))
saveRDS(recipe$feature_names,    file.path(root, "models", "feature_names.rds"))
saveRDS(recipe$factor_levels,    file.path(root, "models", "factor_levels.rds"))
saveRDS(
  list(center = recipe$scaler_center, scale = recipe$scaler_scale,
       log_features = recipe$log_features, num_features = recipe$num_features),
  file.path(root, "models", "scaler.rds")
)

cm_best <- table(True = test_y, Predicted = best_pred)
save_confusion_png(
  cm_best,
  paste0("Official KDDTest+ confusion matrix — ", best_name),
  file.path(root, "figures", "confusion_matrix_best.png")
)

ds <- recipe$downsample
metrics <- list(
  dataset = list(
    source = "NSL-KDD official KDDTrain+ / KDDTest+ split (not reshuffled)",
    n_train_full        = recipe$n_train_full,
    n_train_full_normal = recipe$n_train_full_normal,
    n_train_full_attack = recipe$n_train_full_attack,
    n_test_full         = recipe$n_test_full,
    n_test_full_normal  = recipe$n_test_full_normal,
    n_test_full_attack  = recipe$n_test_full_attack,
    downsample_seed     = ds$seed,
    cap_per_class       = ds$cap_per_class,
    n_fit               = ds$used_n,
    n_fit_normal        = ds$used_normal,
    n_fit_attack        = ds$used_attack,
    selected_features   = recipe$selected_features,
    n_model_columns     = length(recipe$feature_names)
  ),
  rpart         = met_rpart,
  randomForest  = met_rf,
  best_model    = best_name,
  selection_rule = "highest attack recall, then attack F1, then accuracy"
)

# Drop the nested confusion list from JSON (redundant with tn/fp/fn/tp).
metrics$rpart$confusion <- NULL
metrics$randomForest$confusion <- NULL

jsonlite::write_json(
  metrics,
  file.path(root, "models", "metrics.json"),
  pretty = TRUE, auto_unbox = TRUE, digits = 6
)

metrics_csv <- data.frame(
  model            = c(met_rpart$model, met_rf$model),
  accuracy         = c(met_rpart$accuracy, met_rf$accuracy),
  attack_precision = c(met_rpart$attack_precision, met_rf$attack_precision),
  attack_recall    = c(met_rpart$attack_recall, met_rf$attack_recall),
  attack_f1        = c(met_rpart$attack_f1, met_rf$attack_f1),
  normal_precision = c(met_rpart$normal_precision, met_rf$normal_precision),
  normal_recall    = c(met_rpart$normal_recall, met_rf$normal_recall),
  normal_f1        = c(met_rpart$normal_f1, met_rf$normal_f1),
  tn = c(met_rpart$tn, met_rf$tn),
  fp = c(met_rpart$fp, met_rf$fp),
  fn = c(met_rpart$fn, met_rf$fn),
  tp = c(met_rpart$tp, met_rf$tp),
  stringsAsFactors = FALSE
)
utils::write.csv(metrics_csv, file.path(root, "models", "metrics.csv"),
                 row.names = FALSE)

snippet <- c(
  "### Test-set results (official KDDTest+, not reshuffled)",
  "",
  sprintf("Official KDDTrain+ n = %d (normal = %d, attack = %d).",
          recipe$n_train_full, recipe$n_train_full_normal, recipe$n_train_full_attack),
  sprintf("Fit set after majority downsample + cap (seed = %s, cap/class = %s): n = %d (normal = %d, attack = %d).",
          ds$seed, ds$cap_per_class, ds$used_n, ds$used_normal, ds$used_attack),
  sprintf("Official KDDTest+ n = %d (normal = %d, attack = %d).",
          recipe$n_test_full, recipe$n_test_full_normal, recipe$n_test_full_attack),
  sprintf("Raw features = %d. Model columns after dummy encoding = %d.",
          length(recipe$selected_features), length(recipe$feature_names)),
  "",
  "| Model | Accuracy | Attack precision | Attack recall | Attack F1 | Normal precision | Normal recall | Normal F1 |",
  "|-------|----------|------------------|---------------|-----------|------------------|---------------|-----------|",
  sprintf("| rpart decision tree | %s | %s | %s | %s | %s | %s | %s |",
          fmt4(met_rpart$accuracy), fmt4(met_rpart$attack_precision),
          fmt4(met_rpart$attack_recall), fmt4(met_rpart$attack_f1),
          fmt4(met_rpart$normal_precision), fmt4(met_rpart$normal_recall),
          fmt4(met_rpart$normal_f1)),
  sprintf("| Random Forest (ntree = 100) | %s | %s | %s | %s | %s | %s | %s |",
          fmt4(met_rf$accuracy), fmt4(met_rf$attack_precision),
          fmt4(met_rf$attack_recall), fmt4(met_rf$attack_f1),
          fmt4(met_rf$normal_precision), fmt4(met_rf$normal_recall),
          fmt4(met_rf$normal_f1)),
  "",
  sprintf("**Best model saved:** `%s` (selection: highest attack recall, then attack F1, then accuracy).",
          best_name),
  "",
  sprintf("Confusion matrix for %s on KDDTest+: TN (normal→normal) = %d, FP (normal→attack) = %d, FN (attack→normal) = %d, TP (attack→attack) = %d.",
          best_name, best_met$tn, best_met$fp, best_met$fn, best_met$tp)
)
writeLines(snippet, file.path(root, "models", "results_snippet.md"))

message("Wrote models/best_model.rds, metrics.json, metrics.csv, results_snippet.md")
message("Training complete.")
