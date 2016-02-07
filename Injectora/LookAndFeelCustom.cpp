#include "../../JuceLibraryCode/JuceHeader.h"
#include "LookAndFeelCustom.h"

//==============================================================================
LookAndFeelCustom::LookAndFeelCustom()
{
	setColour(TextButton::buttonColourId, Colours::lightgrey);
	setColour(TextButton::textColourOnId, Colours::darkred);
	setColour(TextButton::textColourOffId, Colours::darkred);
	setColour(ListBox::outlineColourId, findColour(ComboBox::outlineColourId));
	setColour(ScrollBar::thumbColourId, Colour(0xffbbbbdd));
	setColour(ScrollBar::backgroundColourId, Colours::transparentBlack);
	setColour(Slider::thumbColourId, Colours::white);
	setColour(Slider::trackColourId, Colour(0x7f000000));
	setColour(Slider::textBoxOutlineColourId, Colours::green);
	setColour(ProgressBar::backgroundColourId, Colours::white.withAlpha(0.6f));
	setColour(ProgressBar::foregroundColourId, Colours::green.withAlpha(0.7f));
	setColour(PopupMenu::backgroundColourId, Colour(0xffeef5f8));
	setColour(PopupMenu::highlightedBackgroundColourId, Colour(0xefb00000)/*Colour(0xbfa4c2ce)*/);
	setColour(PopupMenu::highlightedTextColourId, Colours::white);
	setColour(TextEditor::focusedOutlineColourId, findColour(TextButton::buttonColourId));

	scrollbarShadow.setShadowProperties(DropShadow());
}

LookAndFeelCustom::~LookAndFeelCustom()
{
}

void LookAndFeelCustom::drawTextEditorOutline(Graphics& g, int width, int height, TextEditor& textEditor)
{
	if (textEditor.isEnabled())
	{
		if (textEditor.hasKeyboardFocus(true) && !textEditor.isReadOnly())
		{
			g.setColour(textEditor.findColour(TextEditor::focusedOutlineColourId));
			g.drawRect(0, 0, width, height, 2);
		}
		else
		{
			g.setColour(textEditor.findColour(TextEditor::outlineColourId));
			g.drawRect(0, 0, width, height);
		}
	}
}

void LookAndFeelCustom::drawButtonText(Graphics& g, TextButton& button, bool isMouseOverButton, bool isButtonDown)
{
	Font font(getTextButtonFont(button));
	g.setFont(font);
	if (isMouseOverButton && isButtonDown)
		g.setColour(button.findColour(TextButton::buttonColourId).withMultipliedAlpha(button.isEnabled() ? 1.0f : 0.5f));
	else if (isMouseOverButton)
		g.setColour(button.findColour(button.getToggleState() ? TextButton::textColourOnId : TextButton::textColourOffId).withMultipliedAlpha(button.isEnabled() ? 1.0f : 0.5f));
	else
		g.setColour(button.findColour(button.getToggleState() ? TextButton::textColourOnId : TextButton::textColourOffId).withMultipliedAlpha(button.isEnabled() ? 1.0f : 0.5f));

	const int yIndent = jmin(4, button.proportionOfHeight(0.3f));
	const int cornerSize = jmin(button.getHeight(), button.getWidth()) / 2;

	const int fontHeight = roundToInt(font.getHeight() * 0.6f);
	const int leftIndent = jmin(fontHeight, 2 + cornerSize / (button.isConnectedOnLeft() ? 4 : 2));
	const int rightIndent = jmin(fontHeight, 2 + cornerSize / (button.isConnectedOnRight() ? 4 : 2));
	
	g.drawFittedText(button.getButtonText(), leftIndent, yIndent, button.getWidth() - leftIndent - rightIndent,
		button.getHeight() - yIndent * 2,
		Justification::centred, 2);
}

static void drawButtonShape(Graphics& g, const Path& outline, Colour baseColour, float height)
{
	const float mainBrightness = baseColour.getBrightness();
	const float mainAlpha = baseColour.getFloatAlpha();

	g.setColour(baseColour/*ColourGradient(baseColour.brighter(0.2f), 0.0f, 0.0f, baseColour.darker(0.25f), 0.0f, height, false)*/);
	g.fillPath(outline);

	g.setColour(Colours::white.withAlpha(0.4f * mainAlpha * mainBrightness * mainBrightness));
	g.strokePath(outline, PathStrokeType(1.0f), AffineTransform::translation(0.0f, 1.0f).scaled(1.0f, (height - 1.6f) / height));

	g.setColour(Colours::black.withAlpha(0.4f * mainAlpha));
	g.strokePath(outline, PathStrokeType(1.0f));
}

void LookAndFeelCustom::drawButtonBackground(Graphics& g, Button& button, const Colour& backgroundColour, bool isMouseOverButton, bool isButtonDown)
{
	Colour baseColour(backgroundColour.withMultipliedSaturation(button.hasKeyboardFocus(true) ? 1.3f : 0.9f).withMultipliedAlpha(button.isEnabled() ? 0.9f : 0.5f));

	if (isMouseOverButton || isButtonDown)
		baseColour = Colour(isButtonDown ? button.findColour(TextButton::textColourOnId) : baseColour.contrasting(0.1f));
	else if (button.hasKeyboardFocus(true))
	{
		baseColour = baseColour.darker(0.3f);
	}

	const bool flatOnLeft = button.isConnectedOnLeft();
	const bool flatOnRight = button.isConnectedOnRight();
	const bool flatOnTop = button.isConnectedOnTop();
	const bool flatOnBottom = button.isConnectedOnBottom();

	const float width = button.getWidth() - 1.0f;
	const float height = button.getHeight() - 1.0f;

	if (width > 0 && height > 0)
	{
		const float cornerSize = 4.0f;

		Path outline;
		outline.addRoundedRectangle(0.5f, 0.5f, width, height, cornerSize, cornerSize,
			!(flatOnLeft || flatOnTop),
			!(flatOnRight || flatOnTop),
			!(flatOnLeft || flatOnBottom),
			!(flatOnRight || flatOnBottom));

		drawButtonShape(g, outline, baseColour, height);
		
	}
}

void LookAndFeelCustom::drawTickBox(Graphics& g, Component& /*component*/, float x, float y, float w, float h, const bool ticked, const bool isEnabled, const bool /*isMouseOverButton*/, const bool isButtonDown)
{
	Path box;
	box.addRoundedRectangle(0.0f, 2.0f, 6.0f, 6.0f, 1.0f);

	g.setColour(isEnabled ? Colours::blue.withAlpha(isButtonDown ? 0.3f : 0.1f)
		: Colours::lightgrey.withAlpha(0.1f));

	AffineTransform trans(AffineTransform::scale(w / 9.0f, h / 9.0f).translated(x, y));

	g.fillPath(box, trans);

	g.setColour(Colours::black.withAlpha(0.6f));
	g.strokePath(box, PathStrokeType(0.9f), trans);

	if (ticked)
	{
		Path tick;
		tick.startNewSubPath(1.5f, 3.0f);
		tick.lineTo(3.0f, 6.0f);
		tick.lineTo(6.0f, 0.0f);

		g.setColour(isEnabled ? Colours::black : Colours::grey);
		g.strokePath(tick, PathStrokeType(2.5f), trans);
	}
}

void LookAndFeelCustom::drawToggleButton(Graphics& g, ToggleButton& button, bool isMouseOverButton, bool isButtonDown)
{
	if (button.hasKeyboardFocus(true))
	{
		g.setColour(button.findColour(TextEditor::focusedOutlineColourId));
		g.drawRect(0, 0, button.getWidth(), button.getHeight());
	}

	const int tickWidth = jmin(20, button.getHeight() - 4);

	drawTickBox(g, button, 4.0f, (button.getHeight() - tickWidth) * 0.5f,
		(float)tickWidth, (float)tickWidth,
		button.getToggleState(),
		button.isEnabled(),
		isMouseOverButton,
		isButtonDown);

	g.setColour(button.findColour(ToggleButton::textColourId));
	g.setFont(jmin(15.0f, button.getHeight() * 0.6f));

	if (!button.isEnabled())
		g.setOpacity(0.5f);

	const int textX = tickWidth + 5;

	g.drawFittedText(button.getButtonText(),
		textX, 4,
		button.getWidth() - textX - 2, button.getHeight() - 8,
		Justification::centredLeft, 10);
}

bool LookAndFeelCustom::areScrollbarButtonsVisible()
{
	return false;
}

void LookAndFeelCustom::drawScrollbarButton(Graphics& g, ScrollBar& bar, int width, int height, int buttonDirection, bool isScrollbarVertical, bool isMouseOverButton, bool isButtonDown)
{
	if (bar.isVisible())
	{
		if (isScrollbarVertical)
			width -= 2;
		else
			height -= 2;

		Path p;

		if (buttonDirection == 0)
			p.addTriangle(width * 0.5f, height * 0.2f,
			width * 0.1f, height * 0.7f,
			width * 0.9f, height * 0.7f);
		else if (buttonDirection == 1)
			p.addTriangle(width * 0.8f, height * 0.5f,
			width * 0.3f, height * 0.1f,
			width * 0.3f, height * 0.9f);
		else if (buttonDirection == 2)
			p.addTriangle(width * 0.5f, height * 0.8f,
			width * 0.1f, height * 0.3f,
			width * 0.9f, height * 0.3f);
		else if (buttonDirection == 3)
			p.addTriangle(width * 0.2f, height * 0.5f,
			width * 0.7f, height * 0.1f,
			width * 0.7f, height * 0.9f);

		if (isButtonDown)
			g.setColour(Colours::white);
		else if (isMouseOverButton)
			g.setColour(Colours::white.withAlpha(0.7f));
		else
			g.setColour(bar.findColour(ScrollBar::thumbColourId).withAlpha(0.5f));

		g.fillPath(p);

		g.setColour(Colours::black.withAlpha(0.5f));
		g.strokePath(p, PathStrokeType(0.5f));
	}
}


void LookAndFeelCustom::drawScrollbar(Graphics& g, ScrollBar& scrollbar, int x, int y, int width, int height,
	bool isScrollbarVertical, int thumbStartPosition, int thumbSize, bool isMouseOver, bool isMouseDown)
{
	if (scrollbar.isVisible())
	{
		Path thumbPath;

		if (thumbSize > 0)
		{
			const float thumbIndent = (isScrollbarVertical ? width : height) * 0.25f;
			const float thumbIndentx2 = thumbIndent * 2.0f;

			if (isScrollbarVertical)
				thumbPath.addRectangle(x + thumbIndent, thumbStartPosition + thumbIndent,
				width - thumbIndentx2, thumbSize - thumbIndentx2/*, (width - thumbIndentx2) * 0.5f*/);
			else
				thumbPath.addRectangle(thumbStartPosition + thumbIndent, y + thumbIndent,
				thumbSize - thumbIndentx2, height - thumbIndentx2/*, (height - thumbIndentx2) * 0.5f*/);
		}

		Colour thumbCol(scrollbar.findColour(ScrollBar::thumbColourId, true));

		if (isMouseOver || isMouseDown)
			thumbCol = thumbCol.withMultipliedAlpha(2.0f);

		g.setColour(thumbCol);
		g.fillPath(thumbPath);

		g.setColour(thumbCol.contrasting((isMouseOver || isMouseDown) ? 0.2f : 0.1f));
		g.strokePath(thumbPath, PathStrokeType(1.0f));
	}
}


ImageEffectFilter* LookAndFeelCustom::getScrollbarEffect()
{
	return &scrollbarShadow;
}


void LookAndFeelCustom::drawPopupMenuBackground(Graphics& g, int width, int height)
{
	g.fillAll(findColour(PopupMenu::backgroundColourId));

	g.setColour(Colours::black.withAlpha(0.6f));
	g.drawRect(0, 0, width, height);
}


void LookAndFeelCustom::drawMenuBarBackground(Graphics& g, int /*width*/, int /*height*/,
	bool, MenuBarComponent& menuBar)
{
	g.fillAll(menuBar.findColour(PopupMenu::backgroundColourId));
}


void LookAndFeelCustom::drawComboBox(Graphics& g, int width, int height,
	const bool isButtonDown,
	int buttonX, int buttonY,
	int buttonW, int buttonH,
	ComboBox& box)
{
	g.fillAll(box.findColour(ComboBox::backgroundColourId));

	g.setColour(box.findColour((isButtonDown) ? ComboBox::buttonColourId
		: ComboBox::backgroundColourId));
	g.fillRect(buttonX, buttonY, buttonW, buttonH);

	g.setColour(box.findColour(ComboBox::outlineColourId));
	g.drawRect(0, 0, width, height);

	const float arrowX = 0.2f;
	const float arrowH = 0.3f;

	if (box.isEnabled())
	{
		Path p;
		p.addTriangle(buttonX + buttonW * 0.5f, buttonY + buttonH * (0.45f - arrowH),
			buttonX + buttonW * (1.0f - arrowX), buttonY + buttonH * 0.45f,
			buttonX + buttonW * arrowX, buttonY + buttonH * 0.45f);

		p.addTriangle(buttonX + buttonW * 0.5f, buttonY + buttonH * (0.55f + arrowH),
			buttonX + buttonW * (1.0f - arrowX), buttonY + buttonH * 0.55f,
			buttonX + buttonW * arrowX, buttonY + buttonH * 0.55f);

		g.setColour(box.findColour((isButtonDown) ? ComboBox::backgroundColourId
			: ComboBox::buttonColourId));
		g.fillPath(p);
	}
}

//const Font LookAndFeelCustom::getComboBoxFont(ComboBox& box)
//{
//    Font f (jmin (15.0f, box.getHeight() * 0.85f));
//    f.setHorizontalScale (0.9f);
//    return f;
//}

//==============================================================================
static void drawTriangle(Graphics& g, float x1, float y1, float x2, float y2, float x3, float y3, const Colour& fill, const Colour& outline) noexcept
{
	Path p;
	p.addTriangle(x1, y1, x2, y2, x3, y3);
	g.setColour(fill);
	g.fillPath(p);

	g.setColour(outline);
	g.strokePath(p, PathStrokeType(0.3f));
}

void LookAndFeelCustom::drawLinearSlider(Graphics& g,
	int x, int y, int w, int h,
	float sliderPos, float minSliderPos, float maxSliderPos,
	const Slider::SliderStyle style, Slider& slider)
{
	g.fillAll(slider.findColour(Slider::backgroundColourId));

	if (style == Slider::LinearBar)
	{
		g.setColour(slider.findColour(Slider::thumbColourId));
		g.fillRect(x, y, (int)sliderPos - x, h);

		g.setColour(slider.findColour(Slider::textBoxTextColourId).withMultipliedAlpha(0.5f));
		g.drawRect(x, y, (int)sliderPos - x, h);
	}
	else
	{
		g.setColour(slider.findColour(Slider::trackColourId)
			.withMultipliedAlpha(slider.isEnabled() ? 1.0f : 0.3f));

		if (slider.isHorizontal())
		{
			g.fillRect(x, y + roundToInt(h * 0.8f),
				w, roundToInt(h * 0.2f));
		}
		else
		{
			g.fillRect(x + roundToInt(w * 0.5f - jmin(3.0f, w * 0.1f)), y,
				jmin(4, roundToInt(w * 0.2f)), h);
		}

		float alpha = 0.35f;

		if (slider.isEnabled())
			alpha = slider.isMouseOverOrDragging() ? 1.0f : 0.7f;

		const Colour fill(slider.findColour(Slider::thumbColourId).withAlpha(alpha));
		const Colour outline(Colours::black.withAlpha(slider.isEnabled() ? 0.7f : 0.35f));

		if (style == Slider::TwoValueVertical || style == Slider::ThreeValueVertical)
		{
			drawTriangle(g, x + w * 0.5f + jmin(4.0f, w * 0.3f), minSliderPos,
				x + w * 0.5f - jmin(8.0f, w * 0.4f), minSliderPos - 7.0f,
				x + w * 0.5f - jmin(8.0f, w * 0.4f), minSliderPos,
				fill, outline);

			drawTriangle(g, x + w * 0.5f + jmin(4.0f, w * 0.3f), maxSliderPos,
				x + w * 0.5f - jmin(8.0f, w * 0.4f), maxSliderPos,
				x + w * 0.5f - jmin(8.0f, w * 0.4f), maxSliderPos + 7.0f,
				fill, outline);
		}
		else if (style == Slider::TwoValueHorizontal || style == Slider::ThreeValueHorizontal)
		{
			drawTriangle(g, minSliderPos, y + h * 0.6f - jmin(4.0f, h * 0.3f),
				minSliderPos - 7.0f, y + h * 0.9f,
				minSliderPos, y + h * 0.9f,
				fill, outline);

			drawTriangle(g, maxSliderPos, y + h * 0.6f - jmin(4.0f, h * 0.3f),
				maxSliderPos, y + h * 0.9f,
				maxSliderPos + 7.0f, y + h * 0.9f,
				fill, outline);
		}

		if (style == Slider::LinearHorizontal || style == Slider::ThreeValueHorizontal)
		{
			drawTriangle(g, sliderPos, y + h * 0.9f,
				sliderPos - 7.0f, y + h * 0.2f,
				sliderPos + 7.0f, y + h * 0.2f,
				fill, outline);
		}
		else if (style == Slider::LinearVertical || style == Slider::ThreeValueVertical)
		{
			drawTriangle(g, x + w * 0.5f - jmin(4.0f, w * 0.3f), sliderPos,
				x + w * 0.5f + jmin(8.0f, w * 0.4f), sliderPos - 7.0f,
				x + w * 0.5f + jmin(8.0f, w * 0.4f), sliderPos + 7.0f,
				fill, outline);
		}
	}
}

//Button* LookAndFeelCustom::createSliderButton(const bool isIncrement)
//{
//	if (isIncrement)
//		return new ArrowButton("u", 0.75f, Colours::white.withAlpha(0.8f));
//	else
//		return new ArrowButton("d", 0.25f, Colours::white.withAlpha(0.8f));
//}
//
//ImageEffectFilter* LookAndFeelCustom::getSliderEffect()
//{
//	return &scrollbarShadow;
//}

int LookAndFeelCustom::getSliderThumbRadius(Slider&)
{
	return 8;
}

void LookAndFeelCustom::drawCornerResizer(Graphics& g, int w, int h, bool isMouseOver, bool isMouseDragging)
{
	g.setColour((isMouseOver || isMouseDragging) ? Colours::lightgrey : Colours::darkgrey);

	const float lineThickness = jmin(w, h) * 0.1f;

	for (float i = 0.0f; i < 1.0f; i += 0.3f)
	{
		g.drawLine(w * i, h + 1.0f, w + 1.0f, h * i, lineThickness);
	}
}

Button* LookAndFeelCustom::createDocumentWindowButton(int buttonType)
{
	Path shape;
	if (buttonType == DocumentWindow::closeButton)
	{
		shape.addLineSegment(Line<float>(0.0f, 0.0f, 1.0f, 0.9f), 0.45f);
		shape.addLineSegment(Line<float>(1.0f, 0.0f, 0.0f, 1.0f), 0.35f);

		ShapeButton* const b = new ShapeButton("close", Colour(0x7fff3333), Colour(0xd7ff3333), Colour(0xf7ff3333));

		b->setShape(shape, true, true, true);
		return b;
	}
	else if (buttonType == DocumentWindow::minimiseButton)
	{
		shape.addLineSegment(Line<float>(0.0f, 0.5f, 1.0f, 0.5f), 0.25f);

		DrawableButton* b = new DrawableButton("minimise", DrawableButton::ImageFitted);
		DrawablePath dp;
		dp.setPath(shape);
		dp.setFill(Colours::black.withAlpha(0.3f));
		b->setImages(&dp);
		return b;
	}
	else if (buttonType == DocumentWindow::maximiseButton)
	{
		shape.addLineSegment(Line<float>(0.5f, 0.0f, 0.5f, 1.0f), 0.25f);
		shape.addLineSegment(Line<float>(0.0f, 0.5f, 1.0f, 0.5f), 0.25f);

		DrawableButton* b = new DrawableButton("maximise", DrawableButton::ImageFitted);
		DrawablePath dp;
		dp.setPath(shape);
		dp.setFill(Colours::black.withAlpha(0.3f));
		b->setImages(&dp);
		return b;
	}

	jassertfalse;
	return nullptr;
}

void LookAndFeelCustom::positionDocumentWindowButtons(DocumentWindow& wnd,
	int titleBarX, int titleBarY, int titleBarW, int titleBarH,
	Button* minimiseButton, Button* maximiseButton, Button* closeButton,
	bool positionTitleBarButtonsOnLeft)
{
	titleBarY += titleBarH / 8;
	titleBarH -= titleBarH / 4;

	const int buttonW = titleBarH;

	int x = positionTitleBarButtonsOnLeft ? titleBarX + 4 : titleBarX + titleBarW - buttonW - 4;

	if (closeButton != nullptr)
	{
		closeButton->setBounds(x, titleBarY, buttonW, titleBarH);
		x += positionTitleBarButtonsOnLeft ? buttonW + buttonW / 5 : -(buttonW + buttonW / 5);
	}

	if (positionTitleBarButtonsOnLeft)
		std::swap(minimiseButton, maximiseButton);

	if (maximiseButton != nullptr)
	{
		maximiseButton->setBounds(x, titleBarY - 2, buttonW, titleBarH);
		x += positionTitleBarButtonsOnLeft ? buttonW : -buttonW;
	}

	if (minimiseButton != nullptr)
		minimiseButton->setBounds(x, titleBarY - 2, buttonW, titleBarH);
}