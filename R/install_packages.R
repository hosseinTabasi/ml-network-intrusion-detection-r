# install_packages.R
# Hossein Tabasi
#
# Installs CRAN packages used by this project if they are not already present.
# Run from R:  source("R/install_packages.R")
# Or:          Rscript R/install_packages.R

pkgs <- c(
  "dplyr",
  "ggplot2",
  "readr",
  "tidyr",
  "tibble",
  "caret",
  "randomForest",
  "rpart",
  "shiny",
  "jsonlite"
)

# Cloud CRAN first; fall back to a second mirror if a package fails.
mirrors <- c(
  "https://cloud.r-project.org",
  "https://cran.rstudio.com",
  "https://cran.r-project.org"
)

options(repos = c(CRAN = mirrors[[1]]))

missing <- pkgs[!vapply(pkgs, requireNamespace, logical(1), quietly = TRUE)]

if (length(missing) == 0) {
  message("All required packages are already installed.")
} else {
  message("Installing missing packages: ", paste(missing, collapse = ", "))
  ok_install <- FALSE
  last_err <- NULL
  for (m in mirrors) {
    options(repos = c(CRAN = m))
    message("Trying CRAN mirror: ", m)
    tryCatch({
      install.packages(missing, dependencies = TRUE)
      still <- missing[!vapply(missing, requireNamespace, logical(1), quietly = TRUE)]
      if (length(still) == 0) {
        ok_install <- TRUE
        break
      }
      missing <- still
      last_err <- paste("Still missing after", m, ":", paste(still, collapse = ", "))
    }, error = function(e) {
      last_err <<- conditionMessage(e)
    })
  }
  if (!ok_install) {
    stop("Could not install packages. Last error: ", last_err)
  }
}

ok <- vapply(pkgs, requireNamespace, logical(1), quietly = TRUE)
if (!all(ok)) {
  stop("Failed to install: ", paste(pkgs[!ok], collapse = ", "))
}
message("Package check complete.")
