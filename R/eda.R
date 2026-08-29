# eda.R
# Hossein Tabasi
#
# ggplot2 figures for the official KDDTrain+ table (before downsampling).
# Called from train_models.R; can also be run as:
#   Rscript R/eda.R

run_eda <- function(train_full, figures_dir, selected_num = NUM_FEATURES) {
  dir.create(figures_dir, showWarnings = FALSE, recursive = TRUE)
  theme_set(ggplot2::theme_minimal(base_size = 12))

  # ---- 1. Binary class balance (official train) ----
  bal <- as.data.frame(table(train_full$binary_label), stringsAsFactors = FALSE)
  names(bal) <- c("class", "n")
  bal$class <- factor(bal$class, levels = c("normal", "attack"))
  p_bal <- ggplot2::ggplot(bal, ggplot2::aes(x = class, y = n, fill = class)) +
    ggplot2::geom_col(width = 0.65, colour = "grey20") +
    ggplot2::geom_text(ggplot2::aes(label = format(n, big.mark = ",")),
                       vjust = -0.4, size = 3.5) +
    ggplot2::scale_fill_manual(values = c(normal = "#4C78A8", attack = "#E45756"),
                               guide = "none") +
    ggplot2::scale_y_continuous(expand = ggplot2::expansion(mult = c(0, 0.12))) +
    ggplot2::labs(
      title = "Binary class counts on official KDDTrain+",
      subtitle = "Anything other than label 'normal' is counted as attack",
      x = NULL, y = "Connections"
    )
  ggplot2::ggsave(file.path(figures_dir, "class_balance.png"), p_bal,
                  width = 7, height = 5, dpi = 140)

  # ---- 2. Attack family (EDA only; not a 5-class training target) ----
  fam_levels <- c("normal", "DoS", "Probe", "R2L", "U2R", "other_attack")
  fam <- as.data.frame(table(train_full$attack_family), stringsAsFactors = FALSE)
  names(fam) <- c("family", "n")
  fam$family <- factor(fam$family, levels = fam_levels)
  fam <- fam[!is.na(fam$family), ]
  p_fam <- ggplot2::ggplot(fam, ggplot2::aes(x = family, y = n, fill = family)) +
    ggplot2::geom_col(width = 0.7, colour = "grey20") +
    ggplot2::geom_text(ggplot2::aes(label = format(n, big.mark = ",")),
                       vjust = -0.4, size = 3.2) +
    ggplot2::scale_fill_brewer(palette = "Set2", guide = "none") +
    ggplot2::scale_y_continuous(expand = ggplot2::expansion(mult = c(0, 0.14))) +
    ggplot2::labs(
      title = "Attack-family counts on official KDDTrain+",
      subtitle = "Standard NSL-KDD mapping (DoS / Probe / R2L / U2R). EDA only — models are binary.",
      x = NULL, y = "Connections"
    )
  ggplot2::ggsave(file.path(figures_dir, "attack_family.png"), p_fam,
                  width = 8, height = 5, dpi = 140)

  # ---- 3. Boxplots for five skewed / rate features (log y where needed) ----
  plot_vars <- c("duration", "src_bytes", "dst_bytes", "count", "serror_rate")
  long <- train_full[, c("binary_label", plot_vars)]
  # Sample at most 40k rows so the PNG stays readable and fast.
  set.seed(42)
  if (nrow(long) > 40000) {
    long <- long[sample.int(nrow(long), 40000), ]
  }
  long_t <- tidyr::pivot_longer(long, cols = tidyselect::all_of(plot_vars),
                                names_to = "feature", values_to = "value")
  long_t$feature <- factor(long_t$feature, levels = plot_vars)
  # log1p handles zeros (common for duration / bytes / serror_rate).
  long_t$plot_value <- log1p(pmax(as.numeric(long_t$value), 0))

  p_box <- ggplot2::ggplot(long_t, ggplot2::aes(x = binary_label, y = plot_value,
                                                fill = binary_label)) +
    ggplot2::geom_boxplot(outlier.alpha = 0.08, outlier.size = 0.4, width = 0.6) +
    ggplot2::facet_wrap(~ feature, scales = "free_y", nrow = 2) +
    ggplot2::scale_fill_manual(values = c(normal = "#4C78A8", attack = "#E45756"),
                               guide = "none") +
    ggplot2::labs(
      title = "Selected features by binary class (KDDTrain+, 40k sample)",
      subtitle = "Y-axis is log1p(value) because duration and byte counts are heavily skewed",
      x = NULL, y = "log1p(value)"
    )
  ggplot2::ggsave(file.path(figures_dir, "feature_boxplots.png"), p_box,
                  width = 9, height = 6, dpi = 140)

  # ---- 4. Correlation heatmap of selected numeric features ----
  num <- train_full[, selected_num, drop = FALSE]
  if (nrow(num) > 30000) {
    set.seed(42)
    num <- num[sample.int(nrow(num), 30000), ]
  }
  # Use the same log1p on the heavy tails so Pearson is not dominated by outliers.
  for (nm in intersect(LOG_FEATURES, names(num))) {
    num[[nm]] <- log1p(pmax(as.numeric(num[[nm]]), 0))
  }
  corm <- stats::cor(as.matrix(num), use = "pairwise.complete.obs")
  cordf <- as.data.frame(as.table(corm), stringsAsFactors = FALSE)
  names(cordf) <- c("x", "y", "r")
  cordf$x <- factor(cordf$x, levels = selected_num)
  cordf$y <- factor(cordf$y, levels = rev(selected_num))
  p_cor <- ggplot2::ggplot(cordf, ggplot2::aes(x = x, y = y, fill = r)) +
    ggplot2::geom_tile(colour = "white") +
    ggplot2::scale_fill_gradient2(low = "#4575b4", mid = "white", high = "#d73027",
                                  midpoint = 0, limits = c(-1, 1), name = "r") +
    ggplot2::theme(axis.text.x = ggplot2::element_text(angle = 55, hjust = 1, size = 8),
                   axis.text.y = ggplot2::element_text(size = 8)) +
    ggplot2::labs(
      title = "Pearson correlation of selected numeric features",
      subtitle = "KDDTrain+ sample; duration / src_bytes / dst_bytes are log1p-transformed",
      x = NULL, y = NULL
    )
  ggplot2::ggsave(file.path(figures_dir, "correlation_heatmap.png"), p_cor,
                  width = 9, height = 7.5, dpi = 140)

  message("EDA figures written to ", figures_dir)
  invisible(list(
    class_balance = file.path(figures_dir, "class_balance.png"),
    attack_family = file.path(figures_dir, "attack_family.png"),
    feature_boxplots = file.path(figures_dir, "feature_boxplots.png"),
    correlation_heatmap = file.path(figures_dir, "correlation_heatmap.png")
  ))
}

save_confusion_png <- function(cm_table, title, path) {
  df <- as.data.frame(cm_table, stringsAsFactors = FALSE)
  names(df) <- c("True", "Predicted", "n")
  p <- ggplot2::ggplot(df, ggplot2::aes(x = Predicted, y = True, fill = n)) +
    ggplot2::geom_tile(colour = "white") +
    ggplot2::geom_text(ggplot2::aes(label = format(n, big.mark = ",")), size = 5) +
    ggplot2::scale_fill_gradient(low = "#f7fbff", high = "#08306b", guide = "none") +
    ggplot2::labs(title = title, x = "Predicted", y = "True") +
    ggplot2::theme_minimal(base_size = 13)
  ggplot2::ggsave(path, p, width = 6.5, height = 5, dpi = 140)
  invisible(path)
}

if (sys.nframe() == 0L) {
  args <- commandArgs(trailingOnly = FALSE)
  file_arg <- grep("^--file=", args, value = TRUE)
  this_file <- normalizePath(sub("^--file=", "", file_arg))
  root <- normalizePath(file.path(dirname(this_file), ".."))
  setwd(root)
  source(file.path(root, "R", "prepare_data.R"))
  suppressPackageStartupMessages({
    library(ggplot2)
    library(tidyr)
  })
  raw <- load_nsl_kdd(root)
  run_eda(raw$train, file.path(root, "figures"))
}
