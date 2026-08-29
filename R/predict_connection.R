# predict_connection.R
# Hossein Tabasi
#
# Score one or more NSL-KDD-style connection rows with the files written by
# R/train_models.R. Featurisation is the same recipe used at training time
# (factor levels, dummy columns, log1p, scaler, column order).
#
# Example (from the project root, after training):
#   source("R/prepare_data.R")
#   source("R/predict_connection.R")
#   load_ids_model()
#   predict_connection(list(
#     protocol_type = "tcp", flag = "SF", duration = 0,
#     src_bytes = 232, dst_bytes = 8153, logged_in = 1,
#     count = 5, srv_count = 5, serror_rate = 0
#   ))

.ids_model_env <- new.env(parent = emptyenv())

#' Load RDS model + recipe into a private environment (once per session).
#'
#' @param models_dir directory containing the RDS files (relative to getwd())
load_ids_model <- function(models_dir = "models") {
  needed <- c("best_model.rds", "feature_recipe.rds")
  missing <- needed[!file.exists(file.path(models_dir, needed))]
  if (length(missing) > 0) {
    stop(
      "Missing model files: ", paste(missing, collapse = ", "),
      ". Train first from the project root with:  Rscript R/train_models.R"
    )
  }
  .ids_model_env$model  <- readRDS(file.path(models_dir, "best_model.rds"))
  .ids_model_env$recipe <- readRDS(file.path(models_dir, "feature_recipe.rds"))
  if (inherits(.ids_model_env$model, "randomForest")) {
    suppressPackageStartupMessages(library(randomForest))
  } else if (inherits(.ids_model_env$model, "rpart")) {
    suppressPackageStartupMessages(library(rpart))
  }
  .ids_model_env$ready <- TRUE
  invisible(TRUE)
}

ids_model_ready <- function() {
  isTRUE(.ids_model_env$ready)
}

ids_model_name <- function() {
  m <- .ids_model_env$model
  if (inherits(m, "randomForest")) return("Random Forest")
  if (inherits(m, "rpart"))        return("rpart decision tree")
  paste(class(m), collapse = "/")
}

.row_to_frame <- function(x) {
  if (is.data.frame(x)) return(x)
  if (is.list(x)) {
    # Recycle scalars to a 1-row data.frame.
    return(as.data.frame(x, stringsAsFactors = FALSE))
  }
  if (is.atomic(x) && !is.null(names(x))) {
    return(as.data.frame(as.list(x), stringsAsFactors = FALSE))
  }
  stop("predict_connection() expects a named list, a named vector, or a data.frame.")
}

.predict_prob_attack <- function(model, frame_x) {
  if (inherits(model, "randomForest")) {
    pr <- predict(model, newdata = frame_x, type = "prob")
    return(as.numeric(pr[, "attack"]))
  }
  if (inherits(model, "rpart")) {
    pr <- predict(model, newdata = frame_x, type = "prob")
    return(as.numeric(pr[, "attack"]))
  }
  if (inherits(model, "glm")) {
    return(as.numeric(predict(model, newdata = frame_x, type = "response")))
  }
  stop("Unknown stored model class: ", paste(class(model), collapse = ", "))
}

#' Classify one connection (named list) or many (data.frame).
#'
#' @param x named list / 1-row data.frame, or a data.frame of several rows
#' @param models_dir directory with RDS files
#' @param threshold cut-off on P(attack); default 0.5
#' @return For one row: list(label, probability, note).
#'         For several rows: data.frame(label, probability).
predict_connection <- function(x, models_dir = "models", threshold = 0.5) {
  if (!ids_model_ready()) {
    load_ids_model(models_dir)
  }
  df <- .row_to_frame(x)
  fe <- apply_recipe(df, .ids_model_env$recipe)
  p_att <- .predict_prob_attack(.ids_model_env$model, fe$x)
  lab <- ifelse(p_att >= threshold, "Attack", "Normal")
  model_name <- ids_model_name()

  if (nrow(df) == 1) {
    pct <- sprintf("%.1f%%", 100 * p_att)
    note <- if (lab == "Attack") {
      paste0(
        "Flagged as attack (", model_name, "). Estimated P(attack) ", pct,
        ". This is an offline classifier on recorded NSL-KDD-style features, ",
        "not a live network monitor."
      )
    } else {
      paste0(
        "Looks like a normal connection (", model_name, "). Estimated P(attack) ",
        pct, ". Teaching prototype only — not a production IDS."
      )
    }
    return(list(
      label       = lab,
      probability = unname(p_att),
      note        = note
    ))
  }

  data.frame(
    label       = lab,
    probability = p_att,
    stringsAsFactors = FALSE
  )
}
