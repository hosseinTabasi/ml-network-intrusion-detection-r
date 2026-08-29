# app.R
# Hossein Tabasi
# Shiny front-end for the NSL-KDD binary intrusion detector.
#
# From the project root, after training:
#   shiny::runApp()
#   Rscript -e "shiny::runApp('.', launch.browser = TRUE)"
#
# Teaching prototype only. No packet capture, no live sniffing.

suppressPackageStartupMessages({
  library(shiny)
})

source("R/prepare_data.R", local = TRUE)
source("R/predict_connection.R", local = TRUE)

model_ok <- TRUE
model_error <- NULL
recipe_levels <- list(
  protocol_type = c("tcp", "udp", "icmp"),
  flag = c("SF", "S0", "REJ", "RSTR", "RSTO", "S1", "S2", "S3", "RSTOS0", "SH")
)
tryCatch({
  load_ids_model("models")
  fl <- .ids_model_env$recipe$factor_levels
  if (!is.null(fl$protocol_type)) recipe_levels$protocol_type <- fl$protocol_type
  if (!is.null(fl$flag))          recipe_levels$flag <- fl$flag
}, error = function(e) {
  model_ok    <<- FALSE
  model_error <<- conditionMessage(e)
})

ui <- fluidPage(
  titlePanel("Network Intrusion Detection (NSL-KDD, offline)"),
  tags$p(
    tags$strong("Hossein Tabasi"),
    " — university course project. Classify a recorded connection as",
    " Normal vs Attack from a small set of NSL-KDD features."
  ),
  tags$div(
    style = "background:#fff3cd; border:1px solid #ffc107; padding:10px 14px; margin-bottom:14px;",
    tags$strong("Warning: teaching prototype, not a production IDS."),
    " There is no live packet capture. Do not point this at a real network,",
    " and do not use it to scan or attack systems. Predictions come from a",
    " model trained on the dated NSL-KDD benchmark."
  ),
  sidebarLayout(
    sidebarPanel(
      selectInput("protocol_type", "protocol_type",
                  choices = recipe_levels$protocol_type, selected = "tcp"),
      selectInput("flag", "flag",
                  choices = recipe_levels$flag, selected = "SF"),
      numericInput("duration", "duration (seconds)", value = 0, min = 0, step = 1),
      numericInput("src_bytes", "src_bytes", value = 200, min = 0, step = 1),
      numericInput("dst_bytes", "dst_bytes", value = 1000, min = 0, step = 1),
      numericInput("count", "count (same-host connections in window)",
                   value = 5, min = 0, step = 1),
      numericInput("srv_count", "srv_count (same-service connections in window)",
                   value = 5, min = 0, step = 1),
      sliderInput("serror_rate", "serror_rate", min = 0, max = 1, value = 0, step = 0.01),
      sliderInput("rerror_rate", "rerror_rate", min = 0, max = 1, value = 0, step = 0.01),
      sliderInput("same_srv_rate", "same_srv_rate", min = 0, max = 1, value = 1, step = 0.01),
      selectInput("logged_in", "logged_in",
                  choices = c("0" = 0, "1" = 1), selected = 1),
      numericInput("dst_host_srv_count", "dst_host_srv_count",
                   value = 255, min = 0, max = 255, step = 1),
      actionButton("go", "Predict", class = "btn-primary"),
      tags$hr(),
      fileInput(
        "csv",
        "Optional CSV of connections (columns matching the fields above)",
        accept = c(".csv", "text/csv")
      ),
      tags$p(
        style = "font-size: 0.9em; color: #555;",
        "Unused selected features (for example dest-host error rates) are",
        " filled with training medians / modes so a short form still produces",
        " a complete model row."
      )
    ),
    mainPanel(
      uiOutput("status"),
      tags$h3("Prediction"),
      tags$h2(textOutput("label")),
      tags$p(tags$strong("Estimated P(attack): "), textOutput("prob", inline = TRUE)),
      tags$p(textOutput("note")),
      tags$h3("CSV batch (optional)"),
      tableOutput("batch")
    )
  )
)

server <- function(input, output, session) {
  output$status <- renderUI({
    if (!model_ok) {
      return(tags$p(
        style = "color:#a40000;",
        "Model files are missing. From the project root run ",
        tags$code("Rscript R/train_models.R"),
        ". ", model_error
      ))
    }
    tags$p(style = "color:#555;", "Model loaded from models/best_model.rds.")
  })

  row_from_inputs <- function() {
    list(
      protocol_type       = input$protocol_type,
      flag                = input$flag,
      duration            = as.numeric(input$duration),
      src_bytes           = as.numeric(input$src_bytes),
      dst_bytes           = as.numeric(input$dst_bytes),
      count               = as.numeric(input$count),
      srv_count           = as.numeric(input$srv_count),
      serror_rate         = as.numeric(input$serror_rate),
      rerror_rate         = as.numeric(input$rerror_rate),
      same_srv_rate       = as.numeric(input$same_srv_rate),
      logged_in           = as.numeric(input$logged_in),
      dst_host_srv_count  = as.numeric(input$dst_host_srv_count)
    )
  }

  observeEvent(input$go, {
    if (!model_ok) {
      output$label <- renderText("Train the model first.")
      output$prob  <- renderText("")
      output$note  <- renderText(model_error)
      return()
    }
    res <- predict_connection(row_from_inputs())
    output$label <- renderText(res$label)
    output$prob  <- renderText(sprintf("%.4f", res$probability))
    output$note  <- renderText(res$note)
  })

  output$batch <- renderTable({
    if (!model_ok) return(NULL)
    f <- input$csv
    if (is.null(f)) return(NULL)
    df <- utils::read.csv(f$datapath, stringsAsFactors = FALSE)
    pred <- predict_connection(df)
    cbind(df, pred)
  })
}

shinyApp(ui, server)
